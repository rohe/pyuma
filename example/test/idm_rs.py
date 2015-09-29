#!/usr/bin/env python
import json
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.client import BearerHeader
from oic.utils.keyio import keyjar_init

from uma import PAT
from uma.resourcesrv import ResourceServer1C
from idm import UserInfo

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
        "givenName": "Linda",
        "sn": "Lindgren",
        "email": "linda@example.com",
        "uid": "linda"
    }
}

SCOPES = ["https://dirg.org.umu.se/uma/read"]


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

    dataset = UserInfo(USERDB, config["baseurl"], SCOPES)
    res_srv = ResourceServer1C(dataset, **config)

    jwks = keyjar_init(res_srv, KEYS, "a%d")

    fp = open("static/jwk_rs.json", "w")
    fp.write(json.dumps(jwks))
    fp.close()

    cookie_handler.init_srv(res_srv)

    return res_srv