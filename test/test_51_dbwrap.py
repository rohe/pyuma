import pytest
from uma.message import ResourceSetDescription
from uma.dbwrap.dictdb import DictDBWrap

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


def _eq(l1, l2):
    return set(l1) == set(l2)


class TestDictDBWrap(object):
    @pytest.fixture(autouse=True)
    def create_db(self):
        self.dw = DictDBWrap(USERDB.copy())
        self.dw.scopes2op["https://dirg.org.umu.se/uma/read"] = self.dw.get

    def test_build_resource_set_descriptions(self):
        rsd = self.dw.build_resource_set_descriptions("hans")
        assert len(rsd) == 5
        # Pick one resource set description and check it
        rs = rsd["hans:sn:Granberg"]
        assert isinstance(rs, ResourceSetDescription)
        assert rs["scopes"] == ['https://dirg.org.umu.se/uma/read']
        assert rs['name'] == 'hans sn=Granberg'

    def test_update_resource_set_description_no_change(self):
        _ = self.dw.build_resource_set_descriptions("hans")
        diff = self.dw.update_resource_set_description('hans')
        assert diff == {"delete": [], "add": {}, "update": {}}

    def test_update_resource_set_description_ava_add(self):
        _ = self.dw.build_resource_set_descriptions("hans")
        self.dw.update('hans', {"middleName": "pippi"})
        diff = self.dw.update_resource_set_description('hans')
        assert diff["delete"] == []
        assert diff["update"] == {}

        assert len(diff["add"]) == 1
        assert list(diff['add'].keys())[0] == "hans:middleName:pippi"

    def test_update_resource_set_description_item_del(self):
        _ = self.dw.build_resource_set_descriptions("hans")
        self.dw.delete('hans')
        diff = self.dw.update_resource_set_description('hans')
        assert _eq(diff["delete"],
                   ['hans:eduPersonNickname:Hasse',
                    'hans:displayName:Hans Granberg',
                    'hans:middleName:pippi', 'hans:givenName:Hans',
                    'hans:sn:Granberg',
                    'hans:email:hans@example.org'])
        assert diff["update"] == {}
        assert diff["add"] == {}

    def test_get(self):
        self.dw.update('hans', USERDB["hans"])
        ava = self.dw.get('hans')
        assert _eq(list(ava.keys()),
                   ['sn', 'displayName', 'eduPersonNickname', 'email',
                    'middleName', 'givenName'])
        va = self.dw.get('hans', 'sn')
        assert va == 'Granberg'
