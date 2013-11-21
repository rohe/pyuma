from oic.oic import ProviderConfigurationResponse
from oic.oic import AuthorizationRequest
from oic.oic import RegistrationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import CookieDealer
from uma.message import OIDCProviderConfiguration
from uma.message import PermissionRegistrationRequest
from uma.message import ProviderConfiguration
import uma_rs
import uma_as
from uma.client import Client

AS_PORT = 8088
BASE = "http://localhost:%s" % AS_PORT
AS_CookieHandler = CookieDealer(None)

authzsrv = uma_as.main(BASE, AS_CookieHandler)

RS_PORT = 8089
RS_HOST = "http://localhost:%s" % RS_PORT
RS_CookieHandler = CookieDealer(None)
ressrv = uma_rs.main(RS_HOST, RS_CookieHandler)

print "go!"

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

client.handle_provider_config(oidc_pcr, authzsrv.baseurl, False, False)
opc.update(oidc_pcr)

resp = authzsrv.uma_providerinfo_endpoint()
uma_pcr = ProviderConfiguration().from_json(resp.message)
opc.update(uma_pcr)
client.handle_provider_config(uma_pcr, authzsrv.baseurl, False, False)

client.provider_info[opc["issuer"]] = opc

# Done

# Register the RS as a client to the AS
reg_info = client.create_registration_request(**_me)
reg_resp = authzsrv.registration_endpoint(reg_info.to_json())

regresp = RegistrationResponse() .from_json(reg_resp.message)

print regresp

# Get the PAT, should normally be a login and token request
uid = "linda.lindgren@example.com"
areq = AuthorizationRequest(client_id=regresp["client_id"])
sid = authzsrv.create_authz_session(uid, areq)
grant = authzsrv.sdb[sid]["code"]
_dict = authzsrv.update_to_token(grant)
pat = _dict["access_token"]
ressrv.authz_registration(uid, pat, opc["issuer"])

# create resource set descriptions and register them.
user_info = ressrv.dataset(uid)
desc = uma_rs.build_description(uid, user_info)

# Let the description be consumed by the AS
pat = ressrv.permreg.get(uid, "pat")["access_token"]
request_args = {"access_token": pat}
ht_args = client.client_authn_method[
    "bearer_header"](ressrv).construct(desc, request_args=request_args)

authn = ht_args["authn"]
path = "resource_set/abcdefgh"
authzsrv.resource_set_registration_endpoint(path, "PUT", authn, desc.to_json())