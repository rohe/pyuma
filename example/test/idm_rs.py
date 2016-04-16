#!/usr/bin/env python
import json
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.client import BearerHeader
from oic.utils.keyio import keyjar_init

from uma import PAT
from rest_wrap import RESTIDMWrap
from uma.resource_srv import ResourceServer

__author__ = 'roland'

KEYS = [
    {"type": "RSA", "key": "as.key", "use": ["enc", "sig"]},
]

RES_SRV = None
RP = None

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


def main(base_url, cookie_handler):
    config = {
        "registration_info": {
            "token_endpoint_auth_method": "client_secret_basic",
            "application_type": "web",
            "redirect_uris": ["%s/uma" % base_url],
            "grant_types": ["authorization_code", "implicit"],
            "scope": [PAT],
            "response_types": ["code", "token"]
        },
        "client_authn_method": {
            "client_secret_basic": ClientSecretBasic,
            "bearer_header": BearerHeader
        },
        "flow_type": "code",
        "symkey": "abcdefghijklmnop",
        "baseurl": base_url,
        "scope": PAT
    }

    dataset = RESTIDMWrap(USERDB, baseurl=config["baseurl"])
    res_srv = ResourceServer(dataset, 'alice', {}, **config)

    jwks = keyjar_init(res_srv, KEYS, "a%d")

    fp = open("static/jwk_rs.json", "w")
    fp.write(json.dumps(jwks))
    fp.close()

    cookie_handler.init_srv(res_srv)

    return res_srv