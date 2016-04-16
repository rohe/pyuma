import pytest

from oic.oauth2.util import JSON_ENCODED
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from uma.client import Client
from uma.dbwrap.dictdb import DictDBWrap
from uma.message import ResourceSetDescription
from uma.resource_set import ResourceSetHandler

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
        # The scope to dataset operation map
        dataset.register_scope('https://dirg.org.umu.se/uma/read', 'get')

        client = Client({}, client_authn_methods=CLIENT_AUTHN_METHOD)

        resource_owner = 'hans'
        self.rsh = ResourceSetHandler(dataset, client, resource_owner)

        self.rsh.client.provider_info = {
            "resource_set_registration_endpoint": 'https://as.example.com/rsr'}

        # No the real PAT obviously
        self.rsh.token["PAT"] = 'pat'

        # map client API operation (HTTP GET) to scope
        self.rsh.op2scope = {'GET': 'https://dirg.org.umu.se/uma/read'}

    def test_register_init(self):
        res_set_desc = self.rsh.register_init()
        assert len(res_set_desc) == 5

    def test_com_args(self):
        request_args = {'name': 'gloria',
                        'scopes': ['https://dirg.org.umu.se/uma/read']}
        rsid = 'abcd'
        _kwargs = self.rsh.com_args(ResourceSetDescription, 'PUT',
                                    request_args=request_args,
                                    content_type=JSON_ENCODED,
                                    rsid=rsid)

        assert _kwargs['url'] == 'https://as.example.com/rsr/resource_set/abcd'
        assert _kwargs['body'] in [
            '{"scopes": ["https://dirg.org.umu.se/uma/read"], "name": "gloria"}',
            '{"name": "gloria", "scopes": ["https://dirg.org.umu.se/uma/read"]}'
        ]
        assert _kwargs["http_args"] == {
            'headers': {'Content-Type': 'application/json',
                        'Authorization': 'Bearer pat'}}

    def test_create_rsd(self):
        res_set_desc = self.rsh.register_init()
        # http_args = {'headers': {'Authorization': auth}}
        for lid, _desc in res_set_desc.items():
            res = self.rsh.com_args(ResourceSetDescription, "POST",
                                    request_args=_desc,
                                    content_type=JSON_ENCODED)
            assert res["url"] == 'https://as.example.com/rsr/resource_set'
            assert res["http_args"] == {
                'headers': {'Content-Type': 'application/json',
                            'Authorization': 'Bearer pat'}}

    def test_first_args(self):
        # Used by read and delete
        args = self.rsh.first_args("123456")
        assert args["url"] == 'https://as.example.com/rsr/resource_set/123456'
        assert args["http_args"] == {'headers': {'Authorization': 'Bearer pat'}}

        # used by list
        args = self.rsh.first_args()
        assert args["url"] == 'https://as.example.com/rsr/resource_set'
        assert args["http_args"] == {'headers': {'Authorization': 'Bearer pat'}}

    def test_update_rsd(self):
        res_set_desc = self.rsh.register_init()
        _desc = res_set_desc[list(res_set_desc)[0]]
        res = self.rsh.com_args(ResourceSetDescription, "POST",
                                request_args=_desc, rsid="foo",
                                content_type=JSON_ENCODED)
        assert res["url"] == 'https://as.example.com/rsr/resource_set/foo'
        assert res["http_args"] == {
            'headers': {'Content-Type': 'application/json',
                        'Authorization': 'Bearer pat'}}

    def test_query2permission_registration_request_primer(self):
        self.rsh.register_init()
        _prim = self.rsh.query2permission_registration_request_primer(
            'GET', 'hans', 'attr=givenName')

        assert _prim == [('hans:givenName:Hans',
                          'https://dirg.org.umu.se/uma/read')]
