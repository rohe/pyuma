import json
from urllib.parse import urlparse
from jwkest import b64e_enc_dec
from oic.oauth2.util import JSON_ENCODED
from oic.oic import RegistrationResponse
from oic.oic import AuthorizationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import CookieDealer
from oic.utils.sdb import AuthnEvent
import time
from uma import PAT
from uma.authzsrv import safe_name
from uma.db_wrap import DictDBWrap
from uma.message import ProviderConfiguration, RPTRequest, RQP_CLAIMS_GRANT_TYPE, \
    ClaimToken, RPTResponse, IntrospectionRequest, IntrospectionResponse
from uma.message import PermissionRegistrationRequest
from uma.message import PermissionRegistrationResponse
from uma.message import ResourceSetDescription
from uma.message import StatusResponse
from uma.resourcesrv import ResourceServer

import uma_as
from uma.userinfo import UMAUserInfo

__author__ = 'roland'

# AS init
AS_PORT = 8088
AS_BASE = "https://localhost:%s" % AS_PORT
AS_CookieHandler = CookieDealer(None)

authzsrv = uma_as.main(AS_BASE, AS_CookieHandler)

# RS init

USERDB = {
    "hans": {
        "displayName": "Hans Granberg",
        "givenName": "Hans",
        "sn": "Granberg",
        "eduPersonNickname": "Hasse",
        "email": "hans@example.org",
    },
    "linda": {
        "displayName": "Linda Lindgren",
        "eduPersonNickname": "Linda",
        "givenName": ["Linda", "Maria"],
        "sn": "Lindgren",
        "email": "linda@example.com",
        "uid": "linda"
    }
}

dataset = DictDBWrap(USERDB.copy())
dataset.scopes2op['https://www.example.com/uma/read'] = dataset.get
info_store = {}

RS_PORT = 8089
RS_HOST = "https://localhost:%s" % RS_PORT
ressrv = ResourceServer(dataset, "linda", info_store,
                        client_authn_methods=CLIENT_AUTHN_METHOD)

ressrv.rs_handler.op2scope['GET'] = 'https://www.example.com/uma/read'

# ============================== 1 ===========================================
# Connect RS to AS

# ressrv.client.dynamic(AS_BASE)

# load the UMA AS provider configuration
resp = authzsrv.uma_providerinfo_endpoint()
uma_pcr = ProviderConfiguration().from_json(resp.message)
ressrv.client.handle_provider_config(uma_pcr, authzsrv.baseurl, False, True)

callback = "%s/%s" % (RS_HOST, "auth_cb")

_me = {"application_type": "web", "application_name": "umaclient",
       "contacts": ["ops@example.com"], "redirect_uris": [callback]}

ressrv.client.redirect_uris = [callback]

# Register the RS as a client to the AS, this is OAuth2 dynreg registration
reg_info = ressrv.client.construct_RegistrationRequest(request_args=_me)
reg_resp = authzsrv.oauth_registration_endpoint(reg_info.to_json())
regresp = RegistrationResponse().from_json(reg_resp.message)

ressrv.client.store_registration_info(regresp)

# Get the PAT, should normally be a login and token request
RESOURCE_OWNER = "linda"
identity = {"uid": RESOURCE_OWNER}
areq = AuthorizationRequest(client_id=regresp["client_id"],
                            scope=[PAT])
# Authentication happens by magic :-)
authn_event = AuthnEvent(RESOURCE_OWNER, 'salt',
                         authn_info="UserPassword",
                         time_stamp=int(time.time()))
sid = authzsrv.sdb.create_authz_session(authn_event, areq)
grant = authzsrv.sdb[sid]["code"]
_dict = authzsrv.sdb.upgrade_to_token(grant)
ressrv.rs_handler.token['PAT'] = _dict["access_token"]

# ============================== 2 ===========================================
# create resource set descriptions and register them.
# ressrv.rs_handler.register_resource_set_description({'prim': RESOURCE_OWNER})

res_set_desc = ressrv.rs_handler.dataset.build_resource_set_descriptions(
    RESOURCE_OWNER)

for lid, _desc in res_set_desc.items():
    arg = ressrv.rs_handler.com_args(ResourceSetDescription, "POST",
                                     request_args=_desc,
                                     content_type=JSON_ENCODED)
    authn = arg['http_args']['headers']['Authorization']
    parts = urlparse(arg['url'])
    res = authzsrv.resource_set_registration_endpoint(path=parts.path,
                                                      method="POST",
                                                      authn=authn,
                                                      body=_desc.to_json())
    sr = StatusResponse().from_json(res.message)
    assert res.status == "201 Created"

    # The resource server should keep a map between resource and AS (_rev,_id)
    rsid = sr['_id']
    ressrv.rs_handler.rsd_map[lid] = {'_id': rsid, 'resource_set_desc': _desc}
    ressrv.rs_handler.rsid2lid[rsid] = lid

# ============================== 3 ===========================================
# The client does a first attempt at getting information from the RS
# but without a RPT it only gets information about where the AS is and a ticket.

# The RS on its side registers the necessary permission at the AS
# Assume a HTTP GET with the path+query = linda?attr=sn&attr=givenName

res_set = ressrv.rs_handler.query2permission_registration_request_primer(
    "GET", "linda", "attr=sn&attr=givenName")

pre_rpp = [(ressrv.rs_handler.rsd_map[lid]['_id'], [scope]) for lid, scope in res_set]
REQUESTOR = RESOURCE_OWNER

# -----------------------------------------------------------------------------
# set permissions such that the request below succeeds
owner = safe_name(RESOURCE_OWNER, ressrv.client.client_id)
for rsid, scopes in pre_rpp:
    authzsrv.permit.set_permit(owner, REQUESTOR, rsid, scopes)
# -----------------------------------------------------------------------------

# The client does a first attempt at getting information from the RS
# (not shown here) but without a RPT it only gets information about where
# the AS is.

# The RS on the other hand registers the necessary permission at the AS

prrs = []
for rsid, scopes in pre_rpp:
    prrs.append(PermissionRegistrationRequest(resource_set_id=rsid,
                                              scopes=scopes).to_dict())

pat = ressrv.rs_handler.token['PAT']
resp = authzsrv.permission_registration_endpoint(json.dumps(prrs),
                                                 'Bearer {}'.format(pat))

assert resp.status == "201 Created"

ticket = PermissionRegistrationResponse().from_json(resp.message)["ticket"]

# ============================== 4 ===========================================
# Crank up the client such that the relationship with the AS can be
# settled.
CLI_PORT = 8090
CLI_BASE = "https://localhost:%s" % CLI_PORT

UMA_CLIENT = UMAUserInfo(CLI_BASE, ["%s/authz_cb" % CLI_BASE],
                         "https://localhost:8089", acr="BasicAuthn")

_uma_client = UMA_CLIENT.client

# uma_pcr same as in (1)
_uma_client.handle_provider_config(uma_pcr, authzsrv.baseurl, False, True)

# register at the AS
reg_info = _uma_client.construct_RegistrationRequest(
    request_args=_uma_client.registration_info)
reg_resp = authzsrv.oauth_registration_endpoint(reg_info.to_json())
reginfo = RegistrationResponse().from_json(reg_resp.message)
_uma_client.store_registration_info(reginfo)

# Get a RPT from the AS using the issued client credentials using HTTP Basic
# auth
# (OIDC 'client_secret_basic') combined with the user id of the Requesting Party
# as authentication and the ticket received in (3).

authn = "Basic {}".format(
    b64e_enc_dec(
        "{}:{}".format(_uma_client.client_id, _uma_client.client_secret),
        "ascii", "ascii"))

rqp_claims = b64e_enc_dec(json.dumps({"uid": REQUESTOR}), "utf-8", "ascii")

request = RPTRequest(grant_type=RQP_CLAIMS_GRANT_TYPE, ticket=ticket,
                     claim_tokens=[ClaimToken(format="json", token=rqp_claims)])

resp = authzsrv.rpt_token_endpoint(authn=authn, request=request.to_json())

rtr = RPTResponse().from_json(resp.message)
_uma_client.token[REQUESTOR] = {}
_uma_client.token[REQUESTOR]["RPT"] = rtr["rpt"]

# Introspection of the RPT

pat = ressrv.rs_handler.token['PAT']
_rpt = _uma_client.token[REQUESTOR]["RPT"]
ir = IntrospectionRequest(token=_rpt)

request_args = {"access_token": pat}
ht_args = ressrv.client.client_authn_method[
    "bearer_header"](ressrv).construct(ir, request_args=request_args)

resp = authzsrv.introspection_endpoint(ir.to_json(),
                                       ht_args["headers"]["Authorization"])

iresp = IntrospectionResponse().from_json(resp.message)

assert iresp["active"] is True
assert "permissions" in iresp

res = ressrv.collect_info(iresp, ressrv.rs_handler.op2scope['GET'])

print(res)
