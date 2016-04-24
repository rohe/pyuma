import pytest
from uma.message import AuthzDescription
from uma.permission import Permission

__author__ = 'roland'


def _eq(l1, l2):
    return set(l1) == set(l2)


class TestPerm(object):
    @pytest.fixture(autouse=True)
    def create_db(self):
        self.perm_db = Permission()
        self.perm_db.init_owner('alice')

    def test_permisson_get(self):
        ad = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'write'])
        self.perm_db.set('alice', 'rpt', ad)
        _spec = self.perm_db.get('alice', 'rpt')

        assert _spec[0]["scopes"] == ['read', 'write']
        assert _spec[0]['resource_set_id'] == 'rsid0'

    def test_permisson_get_fail(self):
        ad = AuthzDescription(resource_set_id='rsid', scopes=['read', 'write'])
        self.perm_db.set('alice', 'rpt', ad)

        with pytest.raises(KeyError):
            self.perm_db.get('alice', 'rsid')

        with pytest.raises(KeyError):
            self.perm_db.get('alice', 'xxxx')

    def test_get_request_by_requestor(self):
        ad0 = AuthzDescription(resource_set_id='rsid0',
                               scopes=['read', 'write'])
        ad1 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'exec'])
        self.perm_db.set('alice', 'rpt0', ad0)
        self.perm_db.set('alice', 'rpt1', ad1)

        _spec = self.perm_db.keys('alice')

        assert len(_spec) == 2

    def test_get_requests(self):
        ad0 = AuthzDescription(resource_set_id='rsid0',
                               scopes=['read', 'write'])
        ad1 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'exec'])
        self.perm_db.set('alice', 'rpt0', ad0)
        self.perm_db.set('alice', 'rpt1', ad1)

        _spec = self.perm_db.keys('alice')

        assert _eq(_spec, ['rpt0', 'rpt1'])

    def test_delete_request(self):
        ad0 = AuthzDescription(resource_set_id='rsid0',
                               scopes=['read', 'write'])
        ad1 = AuthzDescription(resource_set_id='rsid0', scopes=['read', 'exec'])
        self.perm_db.set('alice', 'rpt_roger', ad0)
        self.perm_db.set('alice', 'rpt_bob1', ad0)
        self.perm_db.set('alice', 'rpt_bob2', ad1)

        _spec = self.perm_db.keys('alice')
        assert len(_spec) == 3

        self.perm_db.delete_rpt('rpt_bob1')

        _spec = self.perm_db.keys('alice')
        assert _eq(_spec, ['rpt_roger', 'rpt_bob2'])
        _spec = self.perm_db.get('alice', 'rpt_bob2')
        assert len(_spec) == 1

    def test_delete_request_by_resource_id(self):
        ad0 = AuthzDescription(resource_set_id='rsid0',
                               scopes=['read', 'write'])
        ad1 = AuthzDescription(resource_set_id='rsid1', scopes=['read', 'exec'])
        self.perm_db.set('alice', 'rpt_roger', ad0)
        self.perm_db.set('alice', 'rpt_bob1', ad0)
        self.perm_db.set('alice', 'rpt_bob2', ad1)

        self.perm_db.delete_rsid('alice', 'rsid0')

        _spec = self.perm_db.keys('alice')
        assert _spec == ['rpt_bob2']

        _spec = self.perm_db.get('alice', 'rpt_bob2')
        assert len(_spec) == 1
