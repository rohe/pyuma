import pytest

from uma.message import ResourceSetDescription
from uma.resource_set import UnknownObject
from uma.resource_set import MemResourceSetDB

__author__ = 'rolandh'

DB_NAME = "uma"
COLLECTION = "authz"


def test_create():
    rset = MemResourceSetDB(dbname=DB_NAME, collection=COLLECTION)

    rsd = ResourceSetDescription(
        name="Photo Album",
        icon_uri="http://www.example.com/icons/flower.png",
        scopes=[
            "http://photoz.example.com/dev/scopes/view",
            "http://photoz.example.com/dev/scopes/all"],
        type="http://www.example.com/rsets/photoalbum")

    status = rset.create(rsd.to_json(), "oid")
    assert status["_id"]
    assert list(status.keys()) == ["_id"]

    item = rset.read("oid", status["_id"])

    assert isinstance(item, ResourceSetDescription)
    assert item["name"] == rsd["name"]
    assert item["icon_uri"] == rsd["icon_uri"]
    assert item["type"] == rsd["type"]

    with pytest.raises(UnknownObject):
        rset.read("phoney", "id")


def test_update():
    rset = MemResourceSetDB(dbname=DB_NAME, collection=COLLECTION)

    rsd = ResourceSetDescription(
        name="Identity",
        scopes=[
            "http://xenosmilus2.umdc.umu.se/uma/read/name",
            "http://xenosmilus2.umdc.umu.se/uma/read/phone",
            "http://xenosmilus2.umdc.umu.se/uma/read/email",
            "http://xenosmilus2.umdc.umu.se/uma/read/all"
        ])

    status = rset.create(rsd.to_json(), "oid")
    assert status["_id"]

    rsd["scopes"].append("http://xenosmilus2.umdc.umu.se/uma/read/contact")
    rset.update(rsd.to_json(), "oid", status["_id"], )
    after = rset.read("oid", status["_id"])

    assert len(after["scopes"]) == 5


if __name__ == "__main__":
    test_update()
