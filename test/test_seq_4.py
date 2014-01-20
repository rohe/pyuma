from oic.oic import ProviderConfigurationResponse
from oic.oic import AuthorizationRequest
from oic.oic import RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import CookieDealer
from uma.message import OIDCProviderConfiguration
from uma.message import IntrospectionResponse
from uma.message import IntrospectionRequest
from uma.message import RPTResponse
from uma.message import PermissionRegistrationResponse
from uma.message import StatusResponse
from uma.message import PermissionRegistrationRequest
from uma.message import ProviderConfiguration
from uma.userinfo import UMAUserInfo
import uma_rs
import uma_as
from uma.client import Client

AS_PORT = 8088
BASE = "https://localhost:%s" % AS_PORT
AS_CookieHandler = CookieDealer(None)

authzsrv = uma_as.main(BASE, AS_CookieHandler)

RS_PORT = 8089
RS_HOST = "https://localhost:%s" % RS_PORT
RS_CookieHandler = CookieDealer(None)
ressrv = uma_rs.main(RS_HOST, RS_CookieHandler)

print "go!"


def introspect(_client, rsrv, asrv):
    _crpt = _client.token[USER]["RPT"]

    _pat = rsrv.permreg.get(RESOURCE_OWNER, "pat")["access_token"]
    _client_x = rsrv.client[rsrv.permreg.get(RESOURCE_OWNER, "authzsrv")]
    ireq = IntrospectionRequest(token=_crpt)

    req_args = {"access_token": _pat}
    http_args = _client_x.client_authn_method[
        "bearer_header"](rsrv).construct(ireq, request_args=req_args)

    _iresp = asrv.introspection_endpoint(ireq.to_json(),
                                         http_args["headers"]["Authorization"])

    return IntrospectionResponse().from_json(_iresp.message)

# ============================== 1 ===========================================
# teach the RS about what the AS can do and where (=endpoints)

opc = OIDCProviderConfiguration()
resp = authzsrv.providerinfo_endpoint()
oidc_pcr = ProviderConfigurationResponse().from_json(resp.message)

client = Client(
    {},
    client_config={"client_authn_method": CLIENT_AUTHN_METHOD},
    registration_info=ressrv.registration_info)
callback = "%s/%s" % (ressrv.baseurl, "key")
client.redirect_uris = [callback]
_me = ressrv.registration_info.copy()
_me["redirect_uris"] = [callback]

# link to the client
RESSRV_CLI_KEY = "abcdefghijklmn"
ressrv.oic_client[RESSRV_CLI_KEY] = client
ressrv.client[BASE + "/"] = client

client.handle_provider_config(oidc_pcr, authzsrv.baseurl, False, False)
opc.update(oidc_pcr)

resp = authzsrv.uma_providerinfo_endpoint()
uma_pcr = ProviderConfiguration().from_json(resp.message)
opc.update(uma_pcr)
client.handle_provider_config(uma_pcr, authzsrv.baseurl, False, False)

client.provider_info[opc["issuer"]] = opc

# Register the RS as a client to the AS
reg_info = client.create_registration_request(**_me)
reg_resp = authzsrv.registration_endpoint(reg_info.to_json())

regresp = RegistrationResponse().from_json(reg_resp.message)
client.registration_response = regresp
client.client_secret = regresp["client_secret"]
client.client_id = regresp["client_id"]
client.registration_expires = regresp["client_secret_expires_at"]
client.registration_access_token = regresp["registration_access_token"]

# Get the PAT, should normally be a login and token request
RESOURCE_OWNER = "linda"
areq = AuthorizationRequest(client_id=regresp["client_id"])
# Authentication happens by magic :-)
sid = authzsrv.sdb.create_authz_session(RESOURCE_OWNER, areq)
grant = authzsrv.sdb[sid]["code"]
_dict = authzsrv.sdb.update_to_token(grant)
#pat = _dict["access_token"]
ressrv.authz_registration(RESOURCE_OWNER, _dict, opc["issuer"], RESSRV_CLI_KEY)

# ============================== 2 ===========================================
# create resource set descriptions and register them.
user_info = ressrv.dataset(RESOURCE_OWNER)
desc = uma_rs.build_description(RESOURCE_OWNER, user_info)

# Let the description be consumed by the AS
pat = ressrv.permreg.get(RESOURCE_OWNER, "pat")["access_token"]
request_args = {"access_token": pat}
ht_args = client.client_authn_method[
    "bearer_header"](ressrv).construct(desc, request_args=request_args)

authn = ht_args["headers"]["Authorization"]

rsid = "abcdefgh"
as_path = "/resource_set/%s" % rsid
# Simple map between path and rsid, might need a layer of indirection
# link from the path used by the client and the rsid
ressrv.path2rsid["/%s" % RESOURCE_OWNER] = rsid

res = authzsrv.resource_set_registration_endpoint(as_path, "PUT", authn,
                                                  desc.to_json())
sr = StatusResponse().from_json(res.message)
assert sr["status"] == "created"

# The resource server should keep a map between resource and AS (_rev,_id)
ressrv.permreg.set(RESOURCE_OWNER, "registered", sr)
csi = dict(resource_set_descr=desc)
csi["_id"] = sr["_id"]
csi["_rev"] = sr["_rev"]
csi["rsid"] = rsid
ressrv.permreg.add_resource_set_description(RESOURCE_OWNER, csi)

# ============================== 3 ===========================================
# Next step is the user registering permissions
# find all resources !

res_set = authzsrv.resource_sets_by_user(RESOURCE_OWNER)
rs_list = [(r["name"], authzsrv.map_id_rsid[r["_id"]]) for r in res_set]

assert len(rs_list) == 1
assert rs_list[0] == ("linda", "abcdefgh")

rsd = authzsrv.resource_set.read(authzsrv.map_rsid_id["abcdefgh"])

assert rsd["name"] == "linda"

SP_ENTITY_ID_1 = "https://localhost:8092/sp.xml"
SCOPES_1 = ["http://its.umu.se/uma/attr/displayName",
            "http://its.umu.se/uma/attr/uid",
            "http://its.umu.se/uma/attr/email"]

#If something goes wrong I will get an exception otherwise silence !
authzsrv.store_permission(RESOURCE_OWNER, SP_ENTITY_ID_1, rsd["name"], SCOPES_1)

# register another one while on the run
SP_ENTITY_ID_2 = "https://example.com/sp.xml"
SCOPES_2 = ["http://its.umu.se/uma/attr/givenName",
            "http://its.umu.se/uma/attr/sn",
            "http://its.umu.se/uma/attr/email"]

#If something goes wrong I will get an exception otherwise silence !
authzsrv.store_permission(RESOURCE_OWNER, SP_ENTITY_ID_2, rsd["name"], SCOPES_2)

# returns a dictionary with SP entity IDs as keys and resource ids as values
permits = authzsrv.permits_by_user(RESOURCE_OWNER)

assert len(permits) == 2

_rsid = authzsrv.map_id_rsid[rsd["_id"]]

# Get an active permission definition, that is a list of scopes
scopes = authzsrv.permit.get_permit(RESOURCE_OWNER, SP_ENTITY_ID_1, _rsid)

assert scopes == SCOPES_1

scopes = authzsrv.permit.get_permit(RESOURCE_OWNER, SP_ENTITY_ID_2, _rsid)

assert scopes == SCOPES_2

# The first time the Client is active
CLI_PORT = 8090
CLI_BASE = "http://localhost:%s" % CLI_PORT

UMA_CLIENT = UMAUserInfo(CLI_BASE, ["%s/authz_cb" % CLI_BASE],
                         "https://localhost:8089", acr="BasicAuthn")

_uma_client = UMA_CLIENT.client

# ============================== 4 ===========================================
# The client does a first attempt at getting information from the RS
# but without a RPT it only gets information about where the AS is

# Gather AS info
opc = OIDCProviderConfiguration()
_uma_client.handle_provider_config(oidc_pcr, authzsrv.baseurl, False, False)
opc.update(oidc_pcr)
_uma_client.handle_provider_config(uma_pcr, authzsrv.baseurl, False, False)
opc.update(uma_pcr)
_uma_client.provider_info[opc["issuer"]] = opc

# register at AS
reg_info = _uma_client.create_registration_request(
    **_uma_client.registration_info)
reg_resp = authzsrv.registration_endpoint(reg_info.to_json())

reginfo = RegistrationResponse().from_json(reg_resp.message)
_uma_client.store_registration_info(reginfo)

# The user <user name at AS>@<sp entity ID>
USER = "linda@%s" % SP_ENTITY_ID_1

# Get the AAT, should normally be a login and token request
_state = "FOO"
acr = "BasicAuthn"
request_args = {"response_type": "code",
                "client_id": regresp["client_id"],
                "redirect_uri": _uma_client.redirect_uris[0],
                "scope": [_uma_client.get_uma_scope("AAT"), "openid"],
                "state": _state,
                "acr_values": [acr]}

areq = AuthorizationRequest(**request_args)
sid = authzsrv.sdb.create_authz_session(USER, areq)
grant = authzsrv.sdb[sid]["code"]
_uma_client.token[USER] = {"AAT": authzsrv.sdb.update_to_token(grant)}

# Get a RPT from the AS using the AAT as authentication
authn = "Bearer %s" % _uma_client.token[USER]["AAT"]["access_token"]
resp = authzsrv.rpt_endpoint(authn)

rtr = RPTResponse().from_json(resp.message)
_uma_client.token[USER]["RPT"] = rtr["rpt"]

# Client tries to grab some info using the RPT as authn information
# => fails the Resource server registers authz request

# Introspection reveals no permissions are bound to the RPT

ir = introspect(_uma_client, ressrv, authzsrv)

assert ir["active"] is True
assert "permissions" not in ir

# The RS registers an Authorization request
REQ_SCOPES = ["http://its.umu.se/uma/attr/displayName"]
prr = PermissionRegistrationRequest(resource_set_id=_rsid, scopes=REQ_SCOPES)

client, url, ht_args = ressrv.register_init(RESOURCE_OWNER,
                                            "permission_registration_endpoint",
                                            prr, _rsid)

authninfo = ht_args["headers"]["Authorization"]
permresp = authzsrv.permission_registration_endpoint(prr.to_json(), authninfo)
created = PermissionRegistrationResponse().from_json(permresp.message)
_, kwargs = _uma_client.create_authorization_data_request(USER,
                                                          created["ticket"])

request = kwargs["data"]
authn_info = kwargs["headers"]["Authorization"]
res = authzsrv.authorization_request_endpoint(request, authn_info)

assert res.status == "200 OK"

# Now everything should be ready for accessing the resource

# The resource server will do an introspection of the RPT
ir = introspect(_uma_client, ressrv, authzsrv)

assert ir["active"] is True
assert "permissions" in ir

info = ressrv.dataset(RESOURCE_OWNER, ir["permissions"])

assert info == {'displayName': 'Linda Lindgren'}

# =============================================================================
# remove the user defined permission
# =============================================================================

authzsrv.remove_permission(RESOURCE_OWNER, SP_ENTITY_ID_1, rsd["name"])

# Introspection shows the RPT is inactive

ir = introspect(_uma_client, ressrv, authzsrv)

assert ir["active"] is False

# Trying to register a authorization request should fail

REQ_SCOPES = ["http://its.umu.se/uma/attr/displayName"]
prr = PermissionRegistrationRequest(resource_set_id=_rsid, scopes=REQ_SCOPES)

client_y, url_y, ht_args = ressrv.register_init(
    RESOURCE_OWNER, "permission_registration_endpoint", prr, _rsid)

authninfo = ht_args["headers"]["Authorization"]
permresp = authzsrv.permission_registration_endpoint(prr.to_json(), authninfo)
created = PermissionRegistrationResponse().from_json(permresp.message)
_y, kwargs = _uma_client.create_authorization_data_request(USER,
                                                           created["ticket"])

request = kwargs["data"]
authn_info = kwargs["headers"]["Authorization"]
res = authzsrv.authorization_request_endpoint(request, authn_info)

assert res.status == '400 Bad Request'
assert res.message == 'No permission given'
