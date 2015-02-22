#from bson.errors import InvalidId
#from bson.objectid import ObjectId
#import pymongo
import hashlib

from uma.message import ResourceSetDescription, ErrorResponse
from uma.uuid import uuid4
from uma.message import StatusResponse

__author__ = 'rolandh'

RSDkeys = [k for k in ResourceSetDescription.c_param.keys()
           if not k.startswith("_")]


class UnknownObject(Exception):
    pass


class ResourceSetDB(object):
    def __init__(self, **kwargs):
        self.db = None

    def create(self, data, oid):
        raise NotImplemented()

    def read(self, oid, rsid):
        raise NotImplemented()

    def update(self, data, oid, rsid, if_match):
        raise NotImplemented()

    def delete(self, oid, rsid):
        raise NotImplemented()

    def list(self, oid):
        raise NotImplemented()


class MemResourceSetDB(ResourceSetDB):
    def __init__(self, **kwargs):
        ResourceSetDB.__init__(self, **kwargs)
        self.db = {}

    def create(self, data, oid):
        rset = ResourceSetDescription().deserialize(data, "json")
        rset.verify()
        rset.weed()

        # add a revision number
        rset["_rev"] = str(uuid4())
        m = hashlib.md5(rset.to_json())
        rsid = m.hexdigest()

        try:
            self.db[oid][rsid] = rset
        except KeyError:
            self.db[oid] = {rsid: rset}

        status = StatusResponse(_id=rsid, _rev=rset["_rev"],
                                status="created")
        return status

    def read(self, oid, rsid):
        try:
            rset = self.db[oid][rsid]
        except KeyError:
            raise UnknownObject()

        return rset

    def update(self, data, oid, rsid, if_match):
        try:
            rset = self.db[oid][rsid]
        except KeyError:
            raise UnknownObject()

        _new = ResourceSetDescription().deserialize(data, "json")
        _new.weed()
        _new.verify()

        # remove keys I don't allow to be added/updated
        for key in _new.keys():
            if key not in RSDkeys:
                del data[key]

        if _new:
            if if_match != rset["_rev"]:
                status = ErrorResponse(error="precondition_failed")
            else:
                _new["_rev"] = str(uuid4())
                self.db[oid][rsid] = _new

                status = StatusResponse(_id=rsid, _rev=_new["_rev"],
                                        status="updated")
        else:
            status = StatusResponse(_id=rsid, _rev=rset["_rev"],
                                    status="updated")

        return status

    def delete(self, oid, rsid):
        try:
            del self.db[oid][rsid]
        except KeyError:
            raise UnknownObject()

    def list(self, oid):
        return self.db[oid].keys()


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
