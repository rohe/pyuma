import pytest
from uma.message import AuthenticationContext
from uma.message import ErrorDetails
from uma.message import RequestingPartyClaims
from uma.message import RequiredClaims
from uma.permission import Permission

__author__ = 'roland'


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_permisson_get():
    perm_db = Permission()
    perm_db.init_owner('alice')
    perm_db.set('alice', 'alice', 'rsid0', ['read', 'write'])
    _spec = perm_db.get('alice', 'alice', 'rsid0')

    assert _spec["scopes"] == ['read', 'write']
    assert _spec['iat']


def test_permisson_get_fail():
    perm_db = Permission()
    perm_db.init_owner('alice')
    perm_db.set('alice', 'alice', 'rsid', ['read', 'write'])

    with pytest.raises(KeyError):
        perm_db.get('alice', 'bob', 'rsid')

    with pytest.raises(KeyError):
        perm_db.get('alice', 'alice', 'xxxx')

    with pytest.raises(KeyError):
        perm_db.get('bob', 'alice', 'xxxx')


def test_get_request_by_requestor():
    perm_db = Permission()
    perm_db.init_owner('alice')
    perm_db.set('alice', 'alice', 'rsid0', ['read', 'write'])
    perm_db.set('alice', 'alice', 'rsid1', ['read', 'exec'])

    _spec = perm_db.get_request_by_requestor('alice', 'alice')

    assert len(_spec) == 2


def test_get_requests():
    perm_db = Permission()
    perm_db.init_owner('alice')
    perm_db.set('alice', 'alice', 'rsid0', ['read', 'write'])
    perm_db.set('alice', 'bob', 'rsid1', ['read', 'exec'])

    _spec = perm_db.get_requests('alice')

    assert _eq(list(_spec.keys()), ['alice', 'bob'])


def test_delete_request():
    perm_db = Permission()
    perm_db.init_owner('alice')
    perm_db.set('alice', 'alice', 'rsid0', ['read', 'write'])
    perm_db.set('alice', 'bob', 'rsid0', ['read', 'write'])
    perm_db.set('alice', 'bob', 'rsid1', ['read', 'exec'])

    _spec = perm_db.get_request_by_requestor('alice', 'bob')
    assert len(_spec) == 2

    perm_db.delete_request('alice', 'bob', 'rsid1')

    _spec = perm_db.get_requests('alice')
    assert _eq(list(_spec.keys()), ['alice', 'bob'])
    _spec = perm_db.get_request_by_requestor('alice', 'bob')
    assert len(_spec) == 1


def test_delete_request_by_resource_id():
    perm_db = Permission()
    perm_db.init_owner('alice')
    perm_db.set('alice', 'alice', 'rsid0', ['read', 'write'])
    perm_db.set('alice', 'bob', 'rsid0', ['read', 'write'])
    perm_db.set('alice', 'bob', 'rsid1', ['read', 'exec'])

    perm_db.delete_request_by_resource_id('alice', 'rsid0')

    _spec = perm_db.get_requests('alice')
    assert list(_spec.keys()) == ['bob']

    _spec = perm_db.get_request_by_requestor('alice', 'bob')
    assert len(_spec) == 1


def test_set_accepted():
    perm_db = Permission()

    authz = perm_db.construct_authz_desc('rsid', scopes=['read', 'write'])

    # No specific requirements
    perm_db.set_accepted('alice', 'RPT', authz)

    _authz_and_req = perm_db.get_accepted('alice')

    assert len(_authz_and_req) == 1
    assert _authz_and_req['RPT'][0]['desc'] == authz


def test_rm_accepted():
    perm_db = Permission()
    authz = perm_db.construct_authz_desc('rsid', scopes=['read', 'write'])
    perm_db.set_accepted('alice', 'RPT', authz)


def test_set_accepted_with_require():
    perm_db = Permission()

    authz = perm_db.construct_authz_desc('rsid', scopes=['read', 'write'])
    rc = RequiredClaims(
        name="email23423453ou453", friendly_name="email",
        claim_type="urn:oid:0.9.2342.19200300.100.1.3",
        claim_token_format=[
            "http://openid.net/specs/openid-connect-core-1_0.html#IDToken"],
        issuer=["https://example.com/op"])

    rcp = RequestingPartyClaims(
        required_claims=[rc], redirect_user=True,
        ticket='016f84e8-f9b9-11e0-bd6f-0021cc6004de')
    ed = ErrorDetails(requesting_party_claims=rcp,
                      authentication_context=AuthenticationContext(
                          required_acr=["https://example.com/acrs/LOA3.14159"]))

    perm_db.set_accepted('alice', 'RPT', authz, ed)
