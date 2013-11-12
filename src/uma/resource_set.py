from bson import ObjectId
from bson.errors import InvalidId
import pymongo

from uma.message import ResourceSetDescription
from uma.uuid import uuid4
from uma.message import StatusResponse

__author__ = 'rolandh'


class UnknownObject(Exception):
    pass


class ResourceSetDB(object):
    def __init__(self, dbname, collection, host="", port=27017):
        if host:
            self._client = pymongo.MongoClient(host, port)
        else:
            self._client = pymongo.MongoClient()

        self.db = self._client[dbname]

        if collection:
            self.set_collection(collection)
        else:
            self.collection = None

    def set_collection(self, collection):
        self.collection = self.db[collection]

    def read(self, mid):
        try:
            item = self.collection.find_one({"_id": ObjectId(mid)})
        except InvalidId:
            raise UnknownObject()

        # item is dictionary, want _id as string not as ObjectId
        item["_id"] = str(item["_id"])
        rset = ResourceSetDescription(**item)
        return rset

    def find(self, **kwargs):
        item = self.collection.find_one(kwargs)

        if not item:
            raise UnknownObject()

        # item is dictionary, want _id as string not as ObjectId
        item["_id"] = str(item["_id"])
        rset = ResourceSetDescription(**item)
        return rset

    def create(self, data, mid=None):
        # Just to assert that the data is a resource set description
        rset = ResourceSetDescription().deserialize(data, "json")
        # add a revision number
        rset["_rev"] = str(uuid4())
        objid = self.collection.insert(rset.to_dict())
        status = StatusResponse(_id=str(objid), _rev=rset["_rev"],
                                status="created")
        return status

    def update(self, data, mid):
        rset = ResourceSetDescription().deserialize(data, "json")
        try:
            old_rev = rset["_rev"]
        except KeyError:
            try:
                _item = self.collection.find_one({"_id": ObjectId(mid)})
                old_rev = _item["_rev"]
            except InvalidId:
                raise UnknownObject()

        # Assign a new _rev
        rset["_rev"] = str(uuid4())
        result = self.collection.update({"_rev": old_rev}, rset.to_dict())
        assert result["updatedExisting"]
        assert not result["err"]

        status = StatusResponse(_id=mid, _rev=rset["_rev"],
                                status="updated")
        return status

    def delete(self, mid):
        self.collection.remove(ObjectId(mid))

    def list(self):
        _ids = []
        for item in self.collection.find():
            _ids.append(str(item["_id"]))

        return _ids