import json
import time
from urllib.parse import urlparse

from oic.oauth2.util import JSON_ENCODED
from oic.oic import RegistrationResponse
from oic.oic import AuthorizationRequest
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import CookieDealer
from oic.utils.sdb import AuthnEvent

from uma import PAT
from uma.authzsrv import safe_name
from uma.db_wrap import DictDBWrap
from uma.userinfo import UMAUserInfo
from uma.message import ProviderConfiguration
from uma.message import AuthorizationDataRequest
from uma.message import RPTResponse
from uma.message import IntrospectionRequest
from uma.message import IntrospectionResponse
from uma.message import PermissionRegistrationRequest
from uma.message import PermissionRegistrationResponse
from uma.message import ResourceSetDescription
from uma.message import StatusResponse
from uma.resourcesrv import ResourceServer

import uma_as

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

RS_PORT = 8089
RS_HOST = "https://localhost:%s" % RS_PORT
ressrv = ResourceServer(dataset, "linda",
                        client_authn_methods=CLIENT_AUTHN_METHOD)

ressrv.rs_handler.op2scope['GET'] = 'https://www.example.com/uma/read'

# ============================== 1 ===========================================
# Connect RS to AS

# >>> RO->RS: OOB Learn AS location
# >>> RS->AS: UMA1.4 Retrieve AS config data
# >>> AS->RS: UMA1.4 Return AS config data
resp = authzsrv.uma_providerinfo_endpoint()
uma_pcr = ProviderConfiguration().from_json(resp.message)
ressrv.client.handle_provider_config(uma_pcr, authzsrv.baseurl, False, True)

# Setup some RS info (as an RP) to be registered with the AS
callback = "%s/%s" % (RS_HOST, "auth_cb")

_me = {"application_type": "web", "application_name": "umaclient",
       "contacts": ["ops@example.com"], "redirect_uris": [callback]}

ressrv.client.redirect_uris = [callback]

# Register the RS as a client to the AS, this is OAuth2 dynreg registration
# >>> AS->RS: UMA2 Issue client creds(can be dynamic)
reg_info = ressrv.client.construct_RegistrationRequest(request_args=_me)
reg_resp = authzsrv.oauth_registration_endpoint(reg_info.to_json())
regresp = RegistrationResponse().from_json(reg_resp.message)
ressrv.client.store_registration_info(regresp)

# Get the PAT, should normally be a login and token request
# >>> RS->RO: UMA1.3.1 Redirect to AS...
# >>> RO->AS: ...to log in and consent to...
# >>> AS->RS: ...PAT issuance (OAuth scope="uma_protection")\n(can use any grant flow, e.g. implicit or client creds)

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

# >>> RO-->RS: OOB Choose resources to protect
# >>> RO-->AS: OOB Configure policies (can happen after client attempts access)
res_set_desc = ressrv.rs_handler.dataset.build_resource_set_descriptions(
    RESOURCE_OWNER)

# >>> RS->AS: RSR2.2.1 POST /resource_set\nat RSR endpoint with "read" scope
# >>> AS->RS: RSR2.2.1 201 Created; _id in body has {rsid}
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

# >>> RqP-->C: OOB Provision protected resource location
# >>> C->RS: UMA3.1.1 Attempt GET /linda?attr=sn&attr=givenName
res_set = ressrv.rs_handler.query2permission_registration_request_primer(
    "GET", "linda", "attr=sn&attr=givenName")

pre_rpp = [(ressrv.rs_handler.rsd_map[lid]['_id'], [scope]) for lid, scope in
           res_set]
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

# >>> RS->AS: UMA3.2.1 POST requested permission with “read”
# at permission registration endpoint
prrs = []
for rsid, scopes in pre_rpp:
    prrs.append(PermissionRegistrationRequest(resource_set_id=rsid,
                                              scopes=scopes).to_dict())

pat = ressrv.rs_handler.token['PAT']

# >>> AS->RS: UMA3.2.3 Return permission ticket
resp = authzsrv.permission_registration_endpoint(json.dumps(prrs),
                                                 'Bearer {}'.format(pat))

assert resp.status == "201 Created"

ticket = PermissionRegistrationResponse().from_json(resp.message)["ticket"]

# >>> RS->C: UMA3.3.1 Return as_uri and permission ticket

# ============================== 4 ===========================================
# Crank up the Client RP such that the relationship with the AS can be
# settled.
CLI_PORT = 8090
CLI_BASE = "https://localhost:%s" % CLI_PORT

UMA_CLIENT = UMAUserInfo(CLI_BASE, ["%s/authz_cb" % CLI_BASE],
                         "https://localhost:8089", acr="BasicAuthn")

_uma_client = UMA_CLIENT.client

# uma_pcr same as in (1)
# >>> C->AS: UMA1.4 Retrieve AS configuration data
# >>> AS->C: UMA1.4 Return AS config data
_uma_client.handle_provider_config(uma_pcr, authzsrv.baseurl, False, True)

# register at the AS
# >>> AS->C: UMA2 Issue client creds
_state = "FOO"
acr = "BasicAuthn"
request_args = {"response_type": "code",
                "client_id": regresp["client_id"],
                "redirect_uri": _uma_client.redirect_uris[0],
                "scope": [_uma_client.get_uma_scope("AAT")],
                "state": _state,
                "acr_values": [acr]}

# >>> C->RqP: UMA1.3.2 Redirect to AS...
# >>> RqP->AS: ...to log in and consent to...
# >>> AS->C: ...AAT issuance (OAuth scope="uma_authorization")
# (can use any grant flow, e.g. implicit or client creds)

# Fake authentication event
authn_event = AuthnEvent(REQUESTOR, identity.get('salt', ''),
                         authn_info="UserPassword",
                         time_stamp=int(time.time()))

areq = AuthorizationRequest(**request_args)
sid = authzsrv.sdb.create_authz_session(authn_event, areq)
grant = authzsrv.sdb[sid]["code"]
_uma_client.token[REQUESTOR] = {"AAT": authzsrv.sdb.upgrade_to_token(grant)}

# >>> C->AS: UMA3.5.1 POST plain authz data request with
# permission ticket at RPT endpoint

authn = "Bearer %s" % _uma_client.token[REQUESTOR]["AAT"]["access_token"]
request = AuthorizationDataRequest(ticket=ticket)

# >>> AS->C: UMA3.5.3 Return success and RPT
resp = authzsrv.rpt_endpoint(authn, request=request.to_json())

rtr = RPTResponse().from_json(resp.message)
_uma_client.token[REQUESTOR]["RPT"] = rtr["rpt"]

# >>> C->RS: UMA3.1.2 Attempt resource access with RPT

# Introspection of the RPT
# >>> RS->AS: UMA3.4.2 POST to token introspection endpoint
pat = ressrv.rs_handler.token['PAT']
_rpt = _uma_client.token[REQUESTOR]["RPT"]
ir = IntrospectionRequest(token=_rpt)

request_args = {"access_token": pat}
ht_args = ressrv.client.client_authn_method[
    "bearer_header"](ressrv).construct(ir, request_args=request_args)

# >>> AS->RS: UMA3.4.2 Return extended introspection object
resp = authzsrv.introspection_endpoint(ir.to_json(),
                                       ht_args["headers"]["Authorization"])

iresp = IntrospectionResponse().from_json(resp.message)

# >>> RS-->RS: UMA3.3.3 Assess access attempt against
# permissions; has "read" scope

assert iresp["active"] is True
assert "permissions" in iresp

res = ressrv.collect_info(iresp, ressrv.rs_handler.op2scope['GET'])
# >>> RS->C: UMA3.3.3 Enable info reading

print(res)
