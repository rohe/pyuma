import pytest
from uma.message import ResourceSetDescription
from uma.message import StatusResponse
from uma.rsdb import MemResourceSetDB
from uma.rsdb import UnknownObject

RSR_PATH = 'https://example.com'

class TestPerm(object):
    @pytest.fixture(autouse=True)
    def create_db(self):
        self.rsdb = MemResourceSetDB(rsr_path=RSR_PATH, delete_rsid=None)

    def test_create(self):

        rsd = ResourceSetDescription(name='foo', scopes=['read', 'write'])
        res = self.rsdb.create(rsd.to_json(), 'alice')
        assert isinstance(res, StatusResponse)
        assert list(res.keys()) == ['_id']

        _rsd = self.rsdb.read('alice', res['_id'])
        assert _rsd['name'] == 'foo'
        assert _rsd['scopes'] == ['read', 'write']


    def test_create_multi(self):
        rsd = ResourceSetDescription(name='foo', scopes=['read', 'write'])
        res1 = self.rsdb.create(rsd.to_json(), 'alice')
        assert isinstance(res1, StatusResponse)
        assert list(res1.keys()) == ['_id']

        rsd = ResourceSetDescription(name='bar', scopes=['read'])
        res2 = self.rsdb.create(rsd.to_json(), 'bob')
        assert isinstance(res2, StatusResponse)
        assert list(res2.keys()) == ['_id']

        # list all resource set IDs
        assert self.rsdb.list('alice') == [res1['_id']]
        assert self.rsdb.list('bob') == [res2['_id']]

        try:
            self.rsdb.list('cesar')
        except KeyError:
            pass
        else:
            assert False

        _rsd = self.rsdb.read('alice', res1['_id'])
        _rsd['scopes'] = ['read', 'write', 'delete']
        _rsd['type'] = 'application'

        res3 = self.rsdb.update(_rsd.to_json(), 'alice', res1['_id'])

        res4 = self.rsdb.read('alice', res3['_id'])

        assert set(res4.keys()) == {'name', 'scopes', 'type', '_id'}

    def test_from_id(self):
        rsd = ResourceSetDescription(**{
            "name": "Tweedl Social Service",
            "icon_uri": "http://www.example.com/icons/sharesocial.png",
            "scopes": [
                "read-public",
                "post-updates",
                "read-private",
                "http://www.example.com/scopes/all"
            ],
            "type": "http://www.example.com/rsets/socialstream/140-compatible"
        })

        res = self.rsdb.create(rsd.to_json(), 'alice')
        rsid = res['_id']

        resdesc = self.rsdb.read(oid='alice', rsid=rsid)

        assert resdesc['name'] == "Tweedl Social Service"
        assert resdesc['icon_uri'] == 'http://www.example.com/icons/sharesocial.png'
        assert resdesc[
                   'type'] == 'http://www.example.com/rsets/socialstream/140-compatible'
        assert resdesc['scopes'] == [
                "read-public",
                "post-updates",
                "read-private",
                "http://www.example.com/scopes/all"
            ]

        _new = ResourceSetDescription(**{
            "name": "Photo Album",
            "icon_uri": "http://www.example.com/icons/sky.png",
            "scopes": [
                "http://photoz.example.com/dev/scopes/view",
                "public-read"
            ],
            "type": "http://www.example.com/rsets/photoalbum"
        })

        res = self.rsdb.update(data=_new.to_json(), oid='alice', rsid=rsid)

        assert res['_id'] == rsid

        resdesc = self.rsdb.read(oid='alice', rsid=rsid)

        assert resdesc['name'] == "Photo Album"
        assert resdesc['icon_uri'] == 'http://www.example.com/icons/sky.png'
        assert resdesc['type'] == 'http://www.example.com/rsets/photoalbum'
        assert resdesc['scopes'] == [
            "http://photoz.example.com/dev/scopes/view", "public-read"]

        self.rsdb.delete('alice', rsid)

        try:
            self.rsdb.read(oid='alice', rsid=rsid)
        except UnknownObject:
            pass
