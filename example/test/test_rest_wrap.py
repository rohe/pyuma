import pytest
from rest_wrap import RESTIDMWarp

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
        self.riw = RESTIDMWarp(USERDB, baseurl="https://restidm.example.com")

    def test_build_resource_set_descriptions(self):
        rss = self.riw.build_resource_set_descriptions({"user": "linda"})
        print(rss)
        assert len(rss) == 7

    def test_build_resource_set_descriptions_from_subset_of_attributes(self):
        rss = self.riw.build_resource_set_descriptions({"user":"linda"}, attributes=["givenName", "email"])
        assert len(rss) == 3

    def test_query2local_id(self):
        _ = self.riw.build_resource_set_descriptions({"user": "linda"})
        lids = self.riw.query2local_id("linda", "attr=displayName")

        print(lids)
        assert lids == ['linda:displayName:Linda Lindgren']

    def test_query2permission_registration_request_primer(self):
        _ = self.riw.build_resource_set_descriptions({"user": "linda"})
        prim = self.riw.query2permission_registration_request_primer(
            "GET", "linda", "attr=displayName&attr=sn&attr=givenName")

        assert len(prim) == 4

    def test_register_without_value(self):
        lid, rsd = self.riw._register("testuser", "givenName")
        assert rsd["name"] == "testuser givenName"

    def test_register_with_value(self):
        lid, rsd = self.riw._register("testuser", "givenName", "TestUser")
        assert rsd["name"] == "testuser givenName=TestUser"

    def test_register_with_parent(self):
        parent_lid, rsd = self.riw._register("testuser", "givenName")
        child_lid1, rsd = self.riw._register("testuser", "givenName", "TestUser", parent=parent_lid)
        assert self.riw.child_lid[parent_lid] == [child_lid1]

        child_lid2, rsd = self.riw._register("testuser", "givenName", "UserTest", parent=parent_lid)
        assert set(self.riw.child_lid[parent_lid]) == set([child_lid1, child_lid2])
