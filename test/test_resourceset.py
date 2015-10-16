from oic.oauth2.util import JSON_ENCODED
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
import pytest
from uma.client import Client
from uma.db_wrap import DictDBWrap
from uma.message import ResourceSetDescription
from uma.resourceset import ResourceSetHandler

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


class TestResourceSetHandler(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        dataset = DictDBWrap(USERDB)
        client = Client({}, client_authn_methods=CLIENT_AUTHN_METHOD)
        self.rsh = ResourceSetHandler(dataset, client, "hans")
        self.rsh.dataset.scopes2op[
            'https://dirg.org.umu.se/uma/read'] = self.rsh.dataset.get
        self.rsh.client.provider_info = {
            "resource_set_registration_endpoint": 'https://as.example.com/rsr'}

    def test_register_init(self):
        self.rsh.token["PAT"] = 'pat'
        auth, res_set_desc = self.rsh._register_init()
        assert auth == 'Bearer pat'
        assert len(res_set_desc) == 5

    def test_(self):
        self.rsh.token["PAT"] = 'pat'
        auth, res_set_desc = self.rsh._register_init()
        # http_args = {'headers': {'Authorization': auth}}
        for lid, _desc in res_set_desc.items():
            res = self.rsh.com_args(ResourceSetDescription, "POST",
                                    request_args=_desc, auth=auth,
                                    content_type=JSON_ENCODED)
            assert res["url"] == 'https://as.example.com/rsr/resource_set'
            assert res["http_args"] == {
                'headers': {'Content-Type': 'application/json',
                            'Authorization': 'Bearer pat'}}
