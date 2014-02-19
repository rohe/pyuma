from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.client import BearerHeader

from uma import PAT
from uma.json_resource_server import JsonResourceServer
from uma.keyjar import init_keyjar
from uma.resourcesrv import ResourceServer1C

__author__ = 'roland'

KEYS = {
    "RSA": {
        "key": "as.key",
        "usage": ["enc", "sig"]
    }
}

# USERDB = {
#     "hans": {
#         "displayName": "Hans Granberg",
#         "givenName": "Hans",
#         "sn": "Granberg",
#         "eduPersonNickname": "Hasse",
#         "email": "hans@example.org",
#     },
#     "linda": {
#         "displayName": "Linda Lindgren",
#         "eduPersonNickname": "Linda",
#         "givenName": "Linda",
#         "sn": "Lindgren",
#         "email": "linda@example.com",
#         "uid": "linda"
#     }
# }

RES_SRV = None
RP = None


def main(baseurl, cookie_handler):

    config = {
        "registration_info": {
            "token_endpoint_auth_method": "client_secret_basic",
            "application_type": "web",
            "redirect_uris": ["%s/uma" % baseurl],
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
        "baseurl": baseurl,
        "scope": PAT
    }

    #gpii_url = "%s/gpii" % config["base_url"]
    #dataset = IdmUserInfo(USERDB, gpii_url=gpii_url,
    #                      symkey="abcdefghijklmnopqrst")
    dataset = JsonResourceServer(root="resources", base="info", baseurl=baseurl,
                                 owners=["alice"])
    res_srv = ResourceServer1C(dataset, **config)

    init_keyjar(res_srv, KEYS, "static/jwk_rs.json")
    cookie_handler.init_srv(res_srv)

    return res_srv