from uma.message import ResourceSetDescription
from uma.resource_set import UnknownObject
from uma.resource_set import MemResourceSetDB

__author__ = 'rolandh'

DB_NAME = "uma"
COLLECTION = "authz"


def _eq(l1, l2):
    return set(l1) == set(l2)


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

    assert status
    assert status["status"] == "created"
    assert _eq(list(status.keys()), ["status", "_id"])

    item = rset.read("oid", status["_id"])

    assert item
    assert isinstance(item, ResourceSetDescription)
    assert item["name"] == rsd["name"]
    assert item["icon_uri"] == rsd["icon_uri"]
    assert item["type"] == rsd["type"]

    try:
        rset.read("phoney", "id")
        assert False
    except UnknownObject:
        pass


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
    assert status["status"] == "created"

    #before = rset.read(status["_id"], 'oid')

    rsd["scopes"].append("http://xenosmilus2.umdc.umu.se/uma/read/contact")

    status2 = rset.update(rsd.to_json(), "oid", status["_id"], )
    assert status2["status"] == "updated"

    after = rset.read("oid", status["_id"])

    assert len(after["scopes"]) == 5

if __name__ == "__main__":
    test_update()