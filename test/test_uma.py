#!/usr/bin/env python
import base64
import socket
import urllib
from oic.oauth2 import Message
from oic.oic import AuthorizationRequest
from oic.oic import AuthorizationResponse
from oic.oic import AccessTokenRequest
from oic.oic import AccessTokenResponse

from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authn.user import BasicAuthn
#from oic.utils.authn.user import UsernamePasswordMako
#from oic.utils.authn.user_cas import CasAuthnMethod
from oic.utils.authz import Implicit
from oic.utils.keyio import KeyJar
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo
from oic.utils.authn.client import verify_client
from oic.utils.authn.client import BearerHeader
from oic.utils.authn.client import BearerBody
from oic.utils.authn.client import ClientSecretJWT
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.client import ClientSecretPost
from oic.utils.authn.client import PrivateKeyJWT
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.authn_context import UNSPECIFIED
from oic.utils.authn.authn_context import PASSWORD

from uma.authzsrv import Provider
from uma.client import Client
from uma.client import UMA_SCOPE
from uma.message import ProviderConfiguration, IntrospectionRequest
from uma.message import ResourceSetDescription
from uma.message import StatusResponse
from uma.message import RPTResponse
from uma.resourcesrv import ResourceServer

__author__ = 'rolandh'

from mako.lookup import TemplateLookup

ROOT = './'
LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')

CDB = {
    "client_1": {
        "client_secret": "abcdefghijklmnop",
    }
}

USERDB = {
    "user": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "user"
    },
    "username": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "linda"
    }
}
PASSWD = {
    "linda": "krall",
    "user": "howes",
    "https://sp.example.org/": "code"
}

USERINFO = UserInfo(USERDB)


class DummyResponse(object):
    def __init__(self, msg):
        self.status_code = 200
        self.text = msg


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, user="Linda"):
        UserAuthnMethod.__init__(self, srv)
        self.user = user

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}


AUTHZ = Implicit("PERMISSION")

CLIENT_AUTHN_METHOD = {
    "client_secret_basic": ClientSecretBasic,
    "client_secret_post": ClientSecretPost,
    "bearer_header": BearerHeader,
    "bearer_body": BearerBody,
    "client_secret_jwt": ClientSecretJWT,
    "private_key_jwt": PrivateKeyJWT,
}


# =========== INIT the Resource Server ==============

class DataSet(object):
    def __init__(self):
        pass

    def __call__(self, owner, scopes, **kwargs):
        return "Some result"


reginfo = {
    "client_name": "Resource server A",
    "redirect_uris": ["https://rsa.example.com/"],
    "application_type": "web"
}

ressrv = ResourceServer(DataSet(), registration_info=reginfo)

# -------------------- ResourceServer as Client ---------------------

rs_client = Client({}, {"client_authn_method": CLIENT_AUTHN_METHOD})
_me = ressrv.registration_info.copy()
_me["redirect_uris"] = ["https://rs.example.com/"]

# init authsrv

authzsrv = Provider("foo", SessionDB(), CDB, None, AUTHZ,
                    verify_client, "1234567890", keyjar=KeyJar())

authzsrv.baseurl = "https://as.example.com/"

AUTHN_BROKER = AuthnBroker()
AUTHN_BROKER.add(UNSPECIFIED, DummyAuthn(None, user="Linda"), 0,
                 "http://%s" % socket.gethostname())
# AUTHN_BROKER.add(PASSWORD,
#                  UsernamePasswordMako(
#                      None, "login.mako", LOOKUP, PASSWD,
#                      "%s/authorization" % authzsrv.baseurl),
#                  10, "http://%s" % socket.gethostname())
AUTHN_BROKER.add(PASSWORD,
                 BasicAuthn(None, PASSWD),
                 10, "http://%s" % socket.gethostname())

authzsrv.set_authn_broker(AUTHN_BROKER)

ressrv.set_client(authzsrv.baseurl, rs_client)

# -------------------- find authzsrv info --------------------

pcr = ProviderConfiguration().from_json(
    authzsrv.providerinfo_endpoint().message)
rs_client.provider_info[pcr["issuer"]] = pcr
for key, val in pcr.items():
    if key.endswith("_endpoint"):
        setattr(rs_client, key, val)

# -------------------- register client --------------------

rs_client.redirect_uris = _me["redirect_uris"]
http_args, req = rs_client._register(pcr["dynamic_client_endpoint"],
                                  **_me)
resp1 = authzsrv.registration_endpoint(req.to_json())

#regresp = RegistrationResponse().from_json(resp.message)
dresp = DummyResponse(resp1.message)
rs_client.handle_registration_info(dresp)

# -------------- AuthorizationRequest as Resource Owner = Alice ---------------

args = {"response_type": ["code"],
        "scope": ["openid"],
        "state": "STATE"}

#client.do_authorization_request(state="STATE", request_args=args)

url, body, ht_args, csi = rs_client.request_info(
    AuthorizationRequest, "GET", args,
    endpoint=rs_client.provider_info[pcr["issuer"]]["authorization_endpoint"])

resp2 = authzsrv.authorization_endpoint(url.split("?")[1])

aresp = rs_client.parse_response(AuthorizationResponse,
                                 resp2.message.split("?")[1],
                                 sformat="urlencoded")

# get PAT token

args = {
    "grant_type": "authorization_code",
    "code": aresp["code"],
    "redirect_uri": rs_client.redirect_uris[0],
    "client_id": rs_client.client_id,
    "client_secret": rs_client.client_secret
}

url, body, ht_args, csi = rs_client.request_info(
    AccessTokenRequest, "POST", args,
    endpoint=rs_client.provider_info[pcr["issuer"]]["token_endpoint"],
    authn_method="client_secret_basic",
    state=UMA_SCOPE["PAT"])

(_id, _secret) = ht_args["headers"]["auth"]
authn = "Basic %s" % base64.b64encode("%s:%s" % (_id, _secret))

resp3 = authzsrv.token_endpoint(authn, request=body)

atresp = rs_client.parse_response(AccessTokenResponse, resp3.message)

# register information about a resource owner

ressrv.permreg.set("alice", "pat", atresp["access_token"])
ressrv.permreg.set("alice", "authzsrv", pcr["issuer"])

# get the PAT for a specific resource owner

pat = ressrv.permreg.get("alice", "pat")

# resource description

req_args = {"name": "alice@example.com",
            "scopes": ["http_//example.com/scope/read"]}

client, (url, body, ht_args, csi) = ressrv.request_info(
    "alice", ResourceSetDescription, request_args=req_args,
    extra_args={"access_token": pat})

resp4 = authzsrv.resource_set_registration_endpoint("/resource_set/", "PUT",
                                                    body, "Bearer %s" % pat)

status_response = StatusResponse().from_json(resp4.message)

assert status_response["status"] == "created"

# ==================== A while later =========================================

# Try to access a resource

resp = ressrv.dataset_endpoint("/resource_set_id", "alice", {},
                               requestor="https://example.com/sp.xml")

# response is error response with an as_uri claim
# At this point a RPT should be sought by

idp_client = Client({}, {"client_authn_method": CLIENT_AUTHN_METHOD})
reginfo = {
    "client_name": "https://idp.example.com",
    "application_type": "native",
    "redirect_uris": ["https://idp.example.com/uma"]
}

idp_client.redirect_uris = reginfo["redirect_uris"]

idp_client.provider_info[pcr["issuer"]] = pcr
for key, val in pcr.items():
    if key.endswith("_endpoint"):
        setattr(idp_client, key, val)

# register client

http_args, req = idp_client._register(pcr["dynamic_client_endpoint"],
                                      **reginfo)
resp = authzsrv.registration_endpoint(req.to_json())

#regresp = RegistrationResponse().from_json(resp.message)
dresp = DummyResponse(resp.message)
idp_client.handle_registration_info(dresp)

# ---- An AuthorizationRequest on behalf of the requestor == SP -------

request_args = {
    "response_type": ["code"],
    "scope": UMA_SCOPE["AAT"],
    "state": "STATE"
}

#client.do_authorization_request(state="STATE", request_args=args)

REQUESTOR_SP = "https://sp.example.org/"

# Use HTTP basic authn, fake SP username+passwd, should use symmetric key
# to prove client identification

auth_info = base64.b64encode("%s:%s" % (urllib.quote(REQUESTOR_SP), "code"))

url, body, ht_args, csi = idp_client.request_info(
    AuthorizationRequest, "GET", request_args,
    endpoint=client.provider_info[pcr["issuer"]]["authorization_endpoint"],
    headers={"Authorization": auth_info})

resp5 = authzsrv.authorization_endpoint(url.split("?")[1], authn=auth_info)

aresp = idp_client.parse_response(AuthorizationResponse,
                                  resp5.message.split("?")[1],
                                  sformat="urlencoded")

# -------------------- get AAT token --------------------

args = {
    "grant_type": "authorization_code",
    "code": aresp["code"],
    "redirect_uri": idp_client.redirect_uris[0],
    "client_id": idp_client.client_id,
    "client_secret": idp_client.client_secret
}

url, body, ht_args, csi = idp_client.request_info(
    AccessTokenRequest, "POST", args,
    endpoint=idp_client.provider_info[pcr["issuer"]]["token_endpoint"],
    authn_method="client_secret_basic",
    state="STATE",
    scope=UMA_SCOPE["AAT"])

# Client authenticates with HTTP basic authn using client_id&client_secret
(_id, _secret) = ht_args["headers"]["auth"]
authn = "Basic %s" % base64.b64encode("%s:%s" % (_id, _secret))

resp = authzsrv.token_endpoint(authn, request=body)

atresp = idp_client.parse_response(AccessTokenResponse, resp.message)

aat = atresp["access_token"]

# ---
# The access token is specific for a SP
idp_client.aat[REQUESTOR_SP] = atresp

# ------------------- Acquire the RPT -------------------

url, body, ht_args, csi = idp_client.request_info(
    Message, "POST",
    endpoint=idp_client.provider_info[pcr["issuer"]]["rpt_endpoint"],
    authn_method="client_secret_basic",
    access_token=idp_client.aat[REQUESTOR_SP]["access_token"])

resp = authzsrv.token_endpoint(authn, request=body)

atresp = idp_client.parse_response(RPTResponse, resp.message)

idp_client.rpt[REQUESTOR_SP] = atresp

# ---- Access the datasource using the RPT for client authentication -----

_authz = "Bearer %s" % idp_client.rpt[REQUESTOR_SP]["access_token"]

environ = {"HTTP_AUTHORIZATION": _authz}
resp = ressrv.dataset_endpoint("/resource_set_id", "alice", environ,
                               "https://example.com/sp.xml")

##### ---- #####

#ressrv.register_permission("alice", None, "resource_set_id",
#                           ["http_//example.com/scope/read"])

# -- do_introspection

pat = ressrv.permreg.get("alice", "pat")
rpt = idp_client.rpt[REQUESTOR_SP]["access_token"]

request_args = {"token": rpt,
                "resource_id": "resource_set_id"}

client, (url, body, ht_args, csi) = ressrv.request_info(
    "alice", IntrospectionRequest, request_args=request_args,
    extra_args={"access_token": pat})
