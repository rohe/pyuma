# from bson.errors import InvalidId
# from bson.objectid import ObjectId
# import pymongo
import hashlib
import json

from uma.message import ResourceSetResponse
from uma.message import StatusResponse
import uuid

__author__ = 'rolandh'

RSR = [k for k in list(ResourceSetResponse.c_param.keys()) if not k.startswith("_")]


class UnknownObject(Exception):
    pass


class ResourceSetDB(object):
    def __init__(self, **kwargs):
        self.db = None
        self.rsid2oid = {}

    def create(self, data, oid):
        raise NotImplemented()

    def read(self, oid, rsid):
        raise NotImplemented()

    def update(self, data, oid, rsid):
        raise NotImplemented()

    def delete(self, oid, rsid):
        raise NotImplemented()

    def list(self, oid):
        raise NotImplemented()


class MemResourceSetDB(ResourceSetDB):
    def __init__(self, **kwargs):
        ResourceSetDB.__init__(self, **kwargs)
        self.db = {}
        self.etag = {}

    def create(self, data, oid):
        rset = ResourceSetResponse().deserialize(data, "json")
        rset.weed()

        m = hashlib.md5(rset.to_json().encode("utf8"))
        rsid = m.hexdigest()
        rset["_id"] = rsid
        # Need to add _id before verifying
        rset.verify()

        try:
            self.db[oid][rsid] = rset
        except KeyError:
            self.db[oid] = {rsid: rset}

        # backward lookup table
        self.rsid2oid[rsid] = oid

        # add a revision number
        self.etag[rsid] = str(uuid.uuid4())
        status = StatusResponse(_id=rsid)
        return status

    def read(self, oid, rsid):
        try:
            rset = self.db[oid][rsid]
        except KeyError:
            raise UnknownObject()

        return rset

    def update(self, data, oid, rsid):
        try:
            _ = self.db[oid][rsid]
        except KeyError:
            raise UnknownObject()

        _dat = json.loads(data)
        _d = dict([(c, v) for c, v in list(_dat.items()) if c in RSR and c != "_id"])

        _new = ResourceSetResponse(**_d)
        _new["_id"] = rsid
        _new.verify()

        if _new:
            self.db[oid][rsid] = _new
            # new revision
            self.etag[rsid] = str(uuid.uuid4())
            status = StatusResponse(_id=rsid, status="updated")
        else:
            status = StatusResponse(_id=rsid, status="updated")

        return status

    def delete(self, oid, rsid):
        try:
            del self.db[oid][rsid]
        except KeyError:
            raise UnknownObject()

    def list(self, oid):
        return list(self.db[oid].keys())


# class ShelveResourceSetDB(ResourceSetDB):
#     def __init__(self, dbname, **kwargs):
#         ResourceSetDB.__init__(self, **kwargs)
#         self.db = shelve.open(dbname)
#
#     def read(self, mid):
#         try:
#             item = self.collection.find_one({"_id": ObjectId(mid)})
#         except InvalidId:
#             raise UnknownObject()
#
#         # item is dictionary, want _id as string not as ObjectId
#         item["_id"] = str(item["_id"])
#         rset = ResourceSetDescription(**item)
#         return rset
#
#     def find(self, **kwargs):
#         item = self.collection.find_one(kwargs)
#
#         if not item:
#             raise UnknownObject()
#
#         # item is dictionary, want _id as string not as ObjectId
#         item["_id"] = str(item["_id"])
#         rset = ResourceSetDescription(**item)
#         return rset
#
#     def create(self, data, mid=None):
#         # Just to assert that the data is a resource set description
#         rset = ResourceSetDescription().deserialize(data, "json")
#         # add a revision number
#         rset["_rev"] = str(uuid4())
#         objid = self.collection.insert(rset.to_dict())
#         status = StatusResponse(_id=str(objid), _rev=rset["_rev"],
#                                 status="created")
#         return status
#
#     def update(self, data, mid):
#         rset = ResourceSetDescription().deserialize(data, "json")
#         try:
#             old_rev = rset["_rev"]
#         except KeyError:
#             try:
#                 _item = self.collection.find_one({"_id": ObjectId(mid)})
#                 old_rev = _item["_rev"]
#             except InvalidId:
#                 raise UnknownObject()
#
#         # Assign a new _rev
#         rset["_rev"] = str(uuid4())
#         result = self.collection.update({"_rev": old_rev}, rset.to_dict())
#         assert result["updatedExisting"]
#         assert not result["err"]
#
#         status = StatusResponse(_id=mid, _rev=rset["_rev"],
#                                 status="updated")
#         return status
#
#     def delete(self, mid):
#         self.collection.remove(ObjectId(mid))
#
#     def list(self):
#         _ids = []
#         for item in self.collection.find():
#             _ids.append(str(item["_id"]))
#
#         return _ids
#
#     def clean(self):
#         _ids = self.list()
#         for _id in _ids:
#             self.delete(_id)


# class MongoResourceSetDB(object):
#     def __init__(self, dbname, collection, host="", port=27017):
#         if host:
#             self._client = pymongo.MongoClient(host, port)
#         else:
#             self._client = pymongo.MongoClient()
#
#         self.db = self._client[dbname]
#
#         if collection:
#             self.set_collection(collection)
#         else:
#             self.collection = None
#
#     def set_collection(self, collection):
#         self.collection = self.db[collection]
#
#     def read(self, mid):
#         try:
#             item = self.collection.find_one({"_id": ObjectId(mid)})
#         except InvalidId:
#             raise UnknownObject()
#
#         # item is dictionary, want _id as string not as ObjectId
#         item["_id"] = str(item["_id"])
#         rset = ResourceSetDescription(**item)
#         return rset
#
#     def find(self, **kwargs):
#         item = self.collection.find_one(kwargs)
#
#         if not item:
#             raise UnknownObject()
#
#         # item is dictionary, want _id as string not as ObjectId
#         item["_id"] = str(item["_id"])
#         rset = ResourceSetDescription(**item)
#         return rset
#
#     def create(self, data, mid=None):
#         # Just to assert that the data is a resource set description
#         rset = ResourceSetDescription().deserialize(data, "json")
#         # add a revision number
#         rset["_rev"] = str(uuid4())
#         objid = self.collection.insert(rset.to_dict())
#         status = StatusResponse(_id=str(objid), _rev=rset["_rev"],
#                                 status="created")
#         return status
#
#     def update(self, data, mid):
#         rset = ResourceSetDescription().deserialize(data, "json")
#         try:
#             old_rev = rset["_rev"]
#         except KeyError:
#             try:
#                 _item = self.collection.find_one({"_id": ObjectId(mid)})
#                 old_rev = _item["_rev"]
#             except InvalidId:
#                 raise UnknownObject()
#
#         # Assign a new _rev
#         rset["_rev"] = str(uuid4())
#         result = self.collection.update({"_rev": old_rev}, rset.to_dict())
#         assert result["updatedExisting"]
#         assert not result["err"]
#
#         status = StatusResponse(_id=mid, _rev=rset["_rev"],
#                                 status="updated")
#         return status
#
#     def delete(self, mid):
#         self.collection.remove(ObjectId(mid))
#
#     def list(self):
#         _ids = []
#         for item in self.collection.find():
#             _ids.append(str(item["_id"]))
#
#         return _ids
#
#     def clean(self):
#         _ids = self.list()
#         for _id in _ids:
#             self.delete(_id)
