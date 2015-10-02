import time

from oic.oic import ProviderConfigurationResponse
from oic.oic import AuthorizationRequest
from oic.oic import RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import CookieDealer
from oic.utils.sdb import AuthnEvent

import uma_as
from uma.client import Client
from uma.authzsrv import RSR_PATH, safe_name
from uma.message import OIDCProviderConfiguration
from uma.message import AuthorizationDataRequest
from uma.message import IntrospectionResponse
from uma.message import IntrospectionRequest
from uma.message import RPTResponse
from uma.message import PermissionRegistrationResponse
from uma.message import StatusResponse
from uma.message import PermissionRegistrationRequest
from uma.message import ProviderConfiguration
from uma.userinfo import UMAUserInfo

import idm_rs

AS_PORT = 8088
BASE = "https://localhost:%s" % AS_PORT
AS_CookieHandler = CookieDealer(None)

authzsrv = uma_as.main(BASE, AS_CookieHandler)

RS_PORT = 8089
RS_HOST = "https://localhost:%s" % RS_PORT
RS_CookieHandler = CookieDealer(None)
ressrv = idm_rs.main(RS_HOST, RS_CookieHandler)

print("go!")

# ============================== 1 ===========================================
# teach the RS about what the AS can do and where (=endpoints)

opc = OIDCProviderConfiguration()
resp = authzsrv.oidc_providerinfo_endpoint()
oidc_pcr = ProviderConfigurationResponse().from_json(resp.message)

client = Client(
    {},
    client_authn_methods=CLIENT_AUTHN_METHOD)

ressrv.baseurl = RS_HOST
callback = "%s/%s" % (ressrv.baseurl, "key")
client.redirect_uris = [callback]

_me = {"application_type": "web", "application_name": "umaclient",
       "contacts": ["ops@example.com"], "redirect_uris": [callback]}

# link to the client that will talk to the AS
RESSRV_CLI_KEY = "abcdefghijklmn"
ressrv.oidc_client = client
ressrv.client = client

# load the AS provider configuration
# first the OIDC side of the AS
client.handle_provider_config(oidc_pcr, authzsrv.baseurl, False, True)
opc.update(oidc_pcr)

# Then the UMA specific parts
resp = authzsrv.uma_providerinfo_endpoint()
uma_pcr = ProviderConfiguration().from_json(resp.message)
opc.update(uma_pcr)
client.handle_provider_config(uma_pcr, authzsrv.baseurl, False, True)

client.provider_info = opc

# Register the RS as a client to the AS, this is OAuth2 dynreg registration
reg_info = client.construct_RegistrationRequest(request_args=_me)
reg_resp = authzsrv.oidc_registration_endpoint(reg_info.to_json())
regresp = RegistrationResponse().from_json(reg_resp.message)

client.store_registration_info(regresp)

# Get the PAT, should normally be a login and token request
RESOURCE_OWNER = "linda"
identity = {"uid": RESOURCE_OWNER}
areq = AuthorizationRequest(client_id=regresp["client_id"])
# Authentication happens by magic :-)
authn_event = AuthnEvent(RESOURCE_OWNER, identity.get('salt', ''),
                         authn_info="UserPassword",
                         time_stamp=int(time.time()))
sid = authzsrv.sdb.create_authz_session(authn_event, areq)
grant = authzsrv.sdb[sid]["code"]
_dict = authzsrv.sdb.upgrade_to_token(grant)
# pat = _dict["access_token"]
ressrv.authz_registration(RESOURCE_OWNER, _dict, opc["issuer"], RESSRV_CLI_KEY)

# ============================== 2 ===========================================
# create resource set descriptions and register them.
res_set_desc = ressrv.dataset.build_resource_set_descriptions(
    {"user": RESOURCE_OWNER})
ressrv.rsd_map[RESOURCE_OWNER] = {}

# Let the description be consumed by the AS
pat = ressrv.permreg.get(RESOURCE_OWNER, "pat")["access_token"]
request_args = {"access_token": pat}
ht_args = client.client_authn_method[
    "bearer_header"](ressrv).construct({}, request_args=request_args)

authn = ht_args["headers"]["Authorization"]

ro_map = ressrv.rsd_map[RESOURCE_OWNER]
for lid, _desc in res_set_desc:
    res = authzsrv.resource_set_registration_endpoint(path=RSR_PATH,
                                                      method="POST",
                                                      authn=authn,
                                                      body=_desc.to_json())
    sr = StatusResponse().from_json(res.message)
    assert res.status == "201 Created"

    # The resource server should keep a map between resource and AS (_rev,_id)
    ro_map[lid] = {'_id': sr['_id'], 'resource_set_desc': _desc}
    ressrv.rsid2rsd[sr['_id']] = RESOURCE_OWNER, lid

# ============================== 3 ===========================================
# The requestore wants to access some information
# pick up resource sets to work with
res_set = authzsrv.resource_sets_by_user(RESOURCE_OWNER,
                                         ressrv.client.client_id)

# Just pick one resource set id
rsid = res_set[0]['_id']

REQUESTOR = "alice"

# set a permission such that the request below succeeds
owner = safe_name(RESOURCE_OWNER, client.client_id)
authzsrv.permit.set_permit(owner, REQUESTOR, rsid, ressrv.dataset.scopes)

# The client does a first attempt at getting information from the RS
# (not shown here) but without a RPT it only gets information about where
# the AS is.

# The RS on the other hand registers the necessary permission at the AS

prr = PermissionRegistrationRequest(resource_set_id=rsid,
                                    scopes=ressrv.dataset.scopes)

resp = authzsrv.permission_registration_endpoint(prr.to_json(),
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

# Gather AS info, both OIDC OP and UMA AS info
opc = OIDCProviderConfiguration()

# oidc_pcr comes from (1)
_uma_client.handle_provider_config(oidc_pcr, authzsrv.baseurl, False, True)
opc.update(oidc_pcr)

# likewise with uma_pcr
_uma_client.handle_provider_config(uma_pcr, authzsrv.baseurl, False, True)
opc.update(uma_pcr)

_uma_client.provider_info[opc["issuer"]] = opc

# register at the AS
reg_info = _uma_client.construct_RegistrationRequest(
    request_args=_uma_client.registration_info)
reg_resp = authzsrv.oauth_registration_endpoint(reg_info.to_json())

reginfo = RegistrationResponse().from_json(reg_resp.message)
_uma_client.store_registration_info(reginfo)

# Get the AAT, should normally be a login and token request
_state = "FOO"
acr = "BasicAuthn"
request_args = {"response_type": "code",
                "client_id": regresp["client_id"],
                "redirect_uri": _uma_client.redirect_uris[0],
                "scope": [_uma_client.get_uma_scope("AAT"), "openid"],
                "state": _state,
                "acr_values": [acr]}

# Fake authentication event
authn_event = AuthnEvent(REQUESTOR, identity.get('salt', ''),
                         authn_info="UserPassword",
                         time_stamp=int(time.time()))

areq = AuthorizationRequest(**request_args)
sid = authzsrv.sdb.create_authz_session(authn_event, areq)
grant = authzsrv.sdb[sid]["code"]
_uma_client.token[REQUESTOR] = {"AAT": authzsrv.sdb.upgrade_to_token(grant)}

# Get a RPT from the AS using the AAT as authentication and the ticket
# received in (3).

authn = "Bearer %s" % _uma_client.token[REQUESTOR]["AAT"]["access_token"]
request = AuthorizationDataRequest(ticket=ticket)
resp = authzsrv.rpt_endpoint(authn, request=request.to_json())

rtr = RPTResponse().from_json(resp.message)
_uma_client.token[REQUESTOR]["RPT"] = rtr["rpt"]

# Introspection of the RPT

pat = ressrv.permreg.get(RESOURCE_OWNER, "pat")["access_token"]
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

res = ressrv.collect_info(iresp, 'https://dirg.org.umu.se/uma/get')

print(res)
