import pytest
from uma.rest_wrap import RESTIDMWrap

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


class TestRESTIDWrap(object):
    @pytest.fixture(autouse=True)
    def create_wrap(self):
        self.riw = RESTIDMWrap(USERDB, baseurl="https://restidm.example.com")

    def test_build_resource_set_descriptions(self):
        rss = self.riw.build_resource_set_descriptions({"user":"linda"})
        print(rss)
        assert len(rss) == 7

    def test_query2local_id(self):
        _ = self.riw.build_resource_set_descriptions({"user":"linda"})
        lids = self.riw.query2local_id("linda", "attr=displayName")

        print(lids)
        assert lids == ['linda:displayName:Linda Lindgren']

    def test_query2permission_registration_request_primer(self):
        _ = self.riw.build_resource_set_descriptions({"user":"linda"})
        prim = self.riw.query2permission_registration_request_primer(
            "GET", "linda", "attr=displayName&attr=sn&attr=givenName")

        assert len(prim) == 4
