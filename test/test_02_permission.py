import pytest
from uma.message import AuthzDescription
from uma.permission import Permission

__author__ = 'roland'


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_permisson_get():
    perm_db = Permission()
    perm_db.init_owner('alice')
    ad = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'write'])
    perm_db.set('alice', 'rpt', ad)
    _spec = perm_db.get('alice', 'rpt')

    assert _spec[0]["scopes"] == ['read', 'write']
    assert _spec[0]['resource_set_id'] == 'rsid0'


def test_permisson_get_fail():
    perm_db = Permission()
    perm_db.init_owner('alice')
    ad = AuthzDescription(resource_set_id='rsid', scopes=['read', 'write'])
    perm_db.set('alice', 'rpt', ad)

    with pytest.raises(KeyError):
        perm_db.get('alice', 'rsid')

    with pytest.raises(KeyError):
        perm_db.get('alice', 'xxxx')


def test_get_request_by_requestor():
    perm_db = Permission()
    perm_db.init_owner('alice')
    ad0 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'write'])
    ad1 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'exec'])
    perm_db.set('alice', 'rpt0', ad0)
    perm_db.set('alice', 'rpt1', ad1)

    _spec = perm_db.keys('alice')

    assert len(_spec) == 2


def test_get_requests():
    perm_db = Permission()
    perm_db.init_owner('alice')
    ad0 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'write'])
    ad1 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'exec'])
    perm_db.set('alice', 'rpt0', ad0)
    perm_db.set('alice', 'rpt1', ad1)

    _spec = perm_db.keys('alice')

    assert _eq(_spec, ['rpt0', 'rpt1'])


def test_delete_request():
    perm_db = Permission()
    perm_db.init_owner('alice')
    ad0 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'write'])
    ad1 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'exec'])
    perm_db.set('alice', 'rpt_roger', ad0)
    perm_db.set('alice', 'rpt_bob1', ad0)
    perm_db.set('alice', 'rpt_bob2', ad1)

    _spec = perm_db.keys('alice')
    assert len(_spec) == 3

    perm_db.delete_rpt('rpt_bob1')

    _spec = perm_db.keys('alice')
    assert _eq(_spec, ['rpt_roger', 'rpt_bob2'])
    _spec = perm_db.get('alice', 'rpt_bob2')
    assert len(_spec) == 1


def test_delete_request_by_resource_id():
    perm_db = Permission()
    perm_db.init_owner('alice')
    ad0 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'write'])
    ad1 = AuthzDescription(resource_set_id='rsid1', scopes=['read', 'exec'])
    perm_db.set('alice', 'rpt_roger', ad0)
    perm_db.set('alice', 'rpt_bob1', ad0)
    perm_db.set('alice', 'rpt_bob2', ad1)

    perm_db.delete_rsid('alice', 'rsid0')

    _spec = perm_db.keys('alice')
    assert _spec == ['rpt_bob2']

    _spec = perm_db.get('alice', 'rpt_bob2')
    assert len(_spec) == 1

