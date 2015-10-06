from oic.utils.authn.client import ClientSecretBasic, BearerHeader
import pytest
from uma import PAT
from uma.resourcesrv import ResourceServer1C
from uma.rest_wrap import RESTIDMWarp

__author__ = 'roland'

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

BASE_URL = 'https://rest_idm.example.com'

CONFIG = {
    "registration_info": {
        "token_endpoint_auth_method": "client_secret_basic",
        "application_type": "web",
        "redirect_uris": ["%s/uma" % BASE_URL],
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
    "baseurl": BASE_URL,
    "scope": PAT
}


class TestRessrvRESTIDMWrap(object):
    @pytest.fixture(autouse=True)
    def create_wrap(self):
        dataset = RESTIDMWarp(USERDB, baseurl='https://rest_idm.example.com')
        res_srv = ResourceServer1C(dataset, **CONFIG)

    # filter_by_permission(intro, scope=None)
    def test_filter_by_permission(self):
        pass

    # collect_info(self, introspection_response, scope)
    def test_collect_info(self):
        pass
