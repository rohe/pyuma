from uma.message import ResourceSetDescription
from uma.message import StatusResponse
from uma.rsdb import MemResourceSetDB
from uma.rsdb import UnknownObject


def test_create():
    rsdb = MemResourceSetDB()

    rsd = ResourceSetDescription(name='foo', scopes=['read', 'write'])
    res = rsdb.create(rsd.to_json(), 'alice')
    assert isinstance(res, StatusResponse)
    assert list(res.keys()) == ['_id']

    _rsd = rsdb.read('alice', res['_id'])
    assert _rsd['name'] == 'foo'
    assert _rsd['scopes'] == ['read', 'write']


def test_create_multi():
    rsdb = MemResourceSetDB()

    rsd = ResourceSetDescription(name='foo', scopes=['read', 'write'])
    res1 = rsdb.create(rsd.to_json(), 'alice')
    assert isinstance(res1, StatusResponse)
    assert list(res1.keys()) == ['_id']

    rsd = ResourceSetDescription(name='bar', scopes=['read'])
    res2 = rsdb.create(rsd.to_json(), 'bob')
    assert isinstance(res2, StatusResponse)
    assert list(res2.keys()) == ['_id']

    # list all resource set IDs
    assert rsdb.list('alice') == [res1['_id']]
    assert rsdb.list('bob') == [res2['_id']]

    try:
        rsdb.list('cesar')
    except KeyError:
        pass
    else:
        assert False

    _rsd = rsdb.read('alice', res1['_id'])
    _rsd['scopes'] = ['read', 'write', 'delete']
    _rsd['type'] = 'application'

    res3 = rsdb.update(_rsd.to_json(), 'alice', res1['_id'])

    res4 = rsdb.read('alice', res3['_id'])

    assert set(res4.keys()) == {'name', 'scopes', 'type', '_id'}


def test_from_id():
    rsdb = MemResourceSetDB()

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

    res = rsdb.create(rsd.to_json(), 'alice')
    rsid = res['_id']

    resdesc = rsdb.read(oid='alice', rsid=rsid)

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

    res = rsdb.update(data=_new.to_json(), oid='alice', rsid=rsid)

    assert res['_id'] == rsid

    resdesc = rsdb.read(oid='alice', rsid=rsid)

    assert resdesc['name'] == "Photo Album"
    assert resdesc['icon_uri'] == 'http://www.example.com/icons/sky.png'
    assert resdesc['type'] == 'http://www.example.com/rsets/photoalbum'
    assert resdesc['scopes'] == [
        "http://photoz.example.com/dev/scopes/view", "public-read"]

    rsdb.delete('alice', rsid)

    try:
        rsdb.read(oid='alice', rsid=rsid)
    except UnknownObject:
        pass
