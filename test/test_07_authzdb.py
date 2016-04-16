import pytest
from uma.authz_db import MemAuthzDB
from uma.authz_db import UnknownObject
from uma.authz_srv import safe_name
from uma.message import AuthzDescription
from bson.errors import BSONError

__author__ = 'rolandh'

DB_NAME = "rohe0002@umu_se"
COLLECTION = "sso"


def _eq(l1, l2):
    return set(l1) == set(l2)


ATTR = "http://fim.example.com/uma/attr"


@pytest.mark.db
def test_1():
    authz_db = MemAuthzDB(AuthzDescription)
    authz_db.restart()

    rsd = AuthzDescription(
        resource_set_id="https://idp.catalogix.se/id/rohe0002@umu.se",
        entity="https://lingon.ladok.umu.se:8087/sp.xml",
        scopes=[
            "%s/givenName/Roland" % ATTR,
            "%s/surName/Hedberg" % ATTR,
            "%s/displayName/Roland%%20Hedberg" % ATTR,
            "%s/cn/Roland%%20Hedberg" % ATTR,
            "%s/eduPersonScopedAffiliation/member@umu.se" % ATTR,
            "%s/eduPersonScopedAffiliation/employee@umu.se" % ATTR,
            "%s/eduPersonScopedAffiliation/staff@umu.se" % ATTR
        ],
    )

    rid = authz_db.store(rsd.to_json())

    item = authz_db.read(rid)

    assert item
    assert isinstance(item, AuthzDescription)
    for key, val in list(rsd.items()):
        assert key in item
        assert item[key] == val

    try:
        authz_db.read("phoney")
        assert False
    except UnknownObject:
        pass
    except BSONError:
        pass

    res = authz_db.match(
        resource_set_id="https://idp.catalogix.se/id/rohe0002@umu.se",
        entity="https://lingon.ladok.umu.se:8087/sp.xml")

    assert res

    res = authz_db.match(
        resource_set_id="https://idp.catalogix.se/id/rohe0002@umu.se",
        entity="https://lingon.ladok.umu.se:8087/sp.xml",
        scopes=["%s/givenName/Roland" % ATTR])

    assert res

    res = authz_db.match(
        resource_set_id="https://idp.catalogix.se/id/rohe0002@umu.se",
        entity="https://lingon.ladok.umu.se:8087/sp.xml",
        scopes=["%s/sn/Magnusson" % ATTR])

    assert res is False

    res = authz_db.match(
        resource_set_id="https://idp.catalogix.se/id/rohe0002@umu.se",
        entity="https://lingon.catalogix.se:8087/sp.xml")

    assert res is False


@pytest.mark.db
def test_2():
    owner = DB_NAME
    client_id = "http://xenosmilus2.umdc.umu.se:8089/foo"
    collection = safe_name("%s:%s" % (owner, client_id))
    authz_db = MemAuthzDB(AuthzDescription)
    authz_db.restart()


if __name__ == "__main__":
    test_2()
