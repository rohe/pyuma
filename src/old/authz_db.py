from bson import ObjectId
from bson.errors import InvalidId
from oic import rndstr
import pymongo

__author__ = 'rolandh'


class UnknownObject(Exception):
    pass


def is_sub_dict(d1, d2):
    for key in d1.keys():
        if (not key in d2) or (not d1[key] == d2[key]):
            return False
    return True


class Collection(object):
    """
    In memory database that is a list of dictionaries
    """

    def __init__(self):
        self.db = []

    def insert(self, item):
        """
        Insert an item, if the _id already exists in the DB overwrite that
        item

        :param item: dictionary
        """
        if '_id' in item:
            _id = item['_id']
            old_item = self.find_one({'_id': _id})

            if old_item:
                _rev = old_item['_rev']
                item['_rev'] = _rev + 1
                self.db.remove(old_item)
            else:
                if '_rev' not in item:
                    item['_rev'] = 1

            self.db.append(item)
        else:
            _id = rndstr(32)
            item['_id'] = _id
            item['_rev'] = 1
            self.db.append(item)

        return _id

    def find_one(self, pattern):
        for item in self.db:
            if is_sub_dict(pattern, item):
                return item
        raise UnknownObject(pattern)

    def find(self, pattern=None):
        if pattern:
            res = []
            for item in self.db:
                if is_sub_dict(pattern, item):
                    res.append(item)
        else:
            res = self.db

        return res

    def remove(self, iid):
        item = self.find_one({'_id': iid})
        if item:
            _rev = item['_rev']
            self.db.remove(item)


class MemAuthzDB(object):
    def __init__(self, authz_class):
        self.db = Collection()
        self.authz_class = authz_class

    def restart(self):
        self.db = Collection()

    def read(self, rid):
        """
        Read an authorization specification from the database

        :param rid: Resource ID
        :returns: A instance of the authorization class
        """

        pattern = {"_id": rid}
        try:
            item = self.db.find_one(pattern)
        except InvalidId:
            raise UnknownObject()

        rset = self.authz_class(**item)
        return rset

    def store(self, data, rsid=None, rev=None):
        # Just to assert that the data is a resource set description
        rset = self.authz_class().deserialize(data, "json")
        # add a revision number
        if rsid:
            rset['_id'] = rsid
        if rev:
            rset['_rev'] = rev
        return self.db.insert(rset.to_dict())

    def match(self, resource_set_id, entity, scopes=None):
        """

        :param resource_set_id:
        :param entity:
        :param scopes:
        :return: True or False
        """
        # verify the filter
        result = self.db.find({
            "resource_set_id": resource_set_id,
            "entity": entity
        })

        if len(result) == 0:
            return False

        if not scopes:
            return True

        for res in result:
            matched = True
            for scope in scopes:
                try:
                    assert scope in res["scopes"]
                except AssertionError:
                    matched = False
                    break
            if matched:
                return True

        return False

    def delete(self, rsid):
        self.db.remove(rsid)

    def list(self):
        return [item["_id"] for item in self.db.find()]


class MongoAuthzDB(object):
    def __init__(self, authz_class, dbname, collection, host="", port=27017):
        if host:
            self._client = pymongo.MongoClient(host, port)
        else:
            self._client = pymongo.MongoClient()
        self.db = self._client[dbname]
        self.collection = self.db[collection]
        self.authz_class = authz_class

    def restart(self, collection):
        self.db.drop_collection(collection)
        self.collection = self.db[collection]

    def read(self, rid):
        """
        Read an authorization specification from the database
        :param pattern: A search filter that will find at most one item
        :returns: A instance of the authorization class
        """

        pattern = {"_id": ObjectId(rid)}
        try:
            item = self.collection.find_one(pattern)
        except InvalidId:
            raise UnknownObject()

        # item is dictionary, want _id as string not as ObjectId
        item["_id"] = str(item["_id"])
        rset = self.authz_class(**item)
        return rset

    def store(self, data, rsid=None, rev=None):
        # Just to assert that the data is a resource set description
        rset = self.authz_class().deserialize(data, "json")
        # add a revision number
        objid = self.collection.insert(rset.to_dict())
        return str(objid)

    def match(self, resource_set_id, entity, scopes=None):
        """

        :param resource_set_id:
        :param entity:
        :param scopes:
        :return: True or False
        """
        # verify the filter
        result = self.collection.find({
            "resource_set_id": resource_set_id,
            "entity": entity
        })

        if result.count() == 0:
            return False

        if not scopes:
            return True

        for res in result:
            matched = True
            for scope in scopes:
                try:
                    assert scope in res["scopes"]
                except AssertionError:
                    matched = False
                    break
            if matched:
                return True

        return False

    def delete(self, rsid):
        self.collection.remove(ObjectId(rsid))

    def list(self):
        _ids = []
        for item in self.collection.find():
            _ids.append(str(item["_id"]))

        return _ids
