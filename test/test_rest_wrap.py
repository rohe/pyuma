import pytest
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
        "givenName": "Linda",
        "sn": "Lindgren",
        "email": "linda@example.com",
        "uid": "linda"
    }
}


class TestRESTIDWrap(object):
    @pytest.fixture(autouse=True)
    def create_wrap(self):
        self.riw = RESTIDMWarp(USERDB)

    def test_build_resource_set_descriptions(self):
        rss = self.riw.build_resource_set_descriptions("hans")
        print(rss)
        assert len(rss) == 6

    def test_query2local_id(self):
        lids = self.riw.query2local_id("linda", "attr=displayName")

        print(lids)
        assert lids == ['linda:displayName:Linda Lindgren']

