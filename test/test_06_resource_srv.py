import pytest
from uma.dbwrap.dictdb import DictDBWrap
from uma.resource_srv import ResourceServer

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


class TestResourceSetSrv(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        dataset = DictDBWrap(USERDB)
        dataset.register_scope('https://dirg.org.umu.se/uma/read', 'get')

        resource_owner = 'linda'

        self.srv = ResourceServer(dataset, resource_owner)
        # map client API operation (HTTP GET) to scope
        self.srv.rs_handler.op2scope = {
            'GET': 'https://dirg.org.umu.se/uma/read'}

    def test_create_permission_request(self):
        self.srv.rs_handler.register_init()

        # Fake the result of a registration, I skip the resource_set_desc part
        self.srv.rs_handler.rsd_map['linda:sn:Lindgren'] = {'_id': '12345679'}

        prrs = self.srv.create_permission_request('GET', 'linda', 'attr=sn')

        # The needed permissions
        assert prrs == [{'scopes': ['https://dirg.org.umu.se/uma/read'],
                         'resource_set_id': '12345679'}]