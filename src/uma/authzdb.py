from bson import ObjectId
from bson.errors import InvalidId
import pymongo

__author__ = 'rolandh'


class UnknownObject(Exception):
    pass


class AuthzDB(object):
    def __init__(self, authzclass, dbname, collection, host="", port=27017):
        if host:
            self._client = pymongo.MongoClient(host, port)
        else:
            self._client = pymongo.MongoClient()
        self.db = self._client[dbname]
        self.collection = self.db[collection]
        self.authzclass = authzclass

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
        rset = self.authzclass(**item)
        return rset

    def store(self, data, rsid=None, rev=None):
        # Just to assert that the data is a resource set description
        rset = self.authzclass().deserialize(data, "json")
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
            "resource_set_id":resource_set_id,
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