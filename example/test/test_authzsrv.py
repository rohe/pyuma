#!/usr/bin/env python
import base64
import hashlib
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from uma.client import Client
from uma.resourcesrv import ResourceServer1C

__author__ = 'rolandh'


# The UMA Client
reginfo = {
    "client_name": "https://idp.example.com",
    "application_type": "native",
    "redirect_uris": ["https://client.example.com/uma"]
}
CCONF = {"client_authn_method": CLIENT_AUTHN_METHOD}
idp_client = Client({}, CCONF, registration_info=reginfo)

# The UMA RS


class DataSet(object):
    def __init__(self):
        pass

    def __call__(self, owner, scopes, **kwargs):
        return "Some result"

ressrv = ResourceServer1C(DataSet(), registration_info=reginfo)

EPPN = b"foo@example.com"

# A RS client
md = hashlib.md5()
md.update(EPPN)
_key = base64.b16encode(md.digest())

reginfo = {
    "client_name": "https://rs.example.com",
    "application_type": "web",
    "redirect_uris": ["https://rs.example.com/uma/client/%s" % _key]
}

BASE = "http://localhost:8088"

_as = BASE

_client = Client({}, CCONF)
_client.provider_config(_as)
_client.redirect_uris = reginfo["redirect_uris"]
_client.register(
    _client.provider_info[BASE]["dynamic_client_endpoint"], **reginfo)

ressrv.set_client(_key, _client)

# Authorize and get PAT

args = {"response_type": ["code"],
        "scope": ["openid"]}

resp = _client.do_authorization_request(
    state="STATE", request_args=args,
    endpoint=_client.provider_info[BASE]["authorization_request_endpoint"])

# The UMA client after given the AS URL

c_reginfo = {
    "client_name": "https://idp.example.com/uma/client",
    "application_type": "web",
    "redirect_uris": ["https://idp.example.com/uma/client"]
}

idp_client.provider_config(_as)
idp_client.redirect_uris = reginfo["redirect_uris"]
idp_client.register(
    idp_client.provider_info[BASE]["dynamic_client_endpoint"], **reginfo)

# Get AAT and RPT
