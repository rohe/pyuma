import pytest
from uma.authz_db import MemAuthzDB, PDDB
from uma.authz_db import PermissionDescription
from uma.message import AuthzDescription

__author__ = 'rolandh'

DB_NAME = "rohe0002@umu_se"
COLLECTION = "sso"


def _eq(l1, l2):
    return set(l1) == set(l2)


ATTR = "http://fim.example.com/uma/attr"

RSD = PermissionDescription(
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


def test_1():
    authz_db = MemAuthzDB()

    rid = authz_db.store(RSD)

    item = authz_db.find_one({'_id': rid})

    assert item
    assert isinstance(item, PermissionDescription)
    for key, val in list(RSD.items()):
        assert key in item
        assert item[key] == val

    assert authz_db.read(resource_set_id="phoney") == []

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

    rols = authz_db.read(entity="https://lingon.ladok.umu.se:8087/sp.xml")

    assert rols

    authz_db.remove(pdid=rid)

    assert authz_db.match(
        resource_set_id="https://idp.catalogix.se/id/rohe0002@umu.se",
        entity="https://lingon.ladok.umu.se:8087/sp.xml") == False


def test_2():
    _db = PDDB()

    _db.add('roland', RSD)


    res = authz_db.match(
        resource_set_id="https://idp.catalogix.se/id/rohe0002@umu.se",
        entity="https://lingon.ladok.umu.se:8087/sp.xml")

    assert res
