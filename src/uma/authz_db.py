# import pymongo
#
# from bson import ObjectId
# from bson.errors import InvalidId

from oic import rndstr
from oic.oauth2 import SINGLE_OPTIONAL_INT
from oic.oauth2 import SINGLE_REQUIRED_STRING

from uma.message import AuthzDescription

__author__ = 'rolandh'


class UnknownObject(Exception):
    pass


def is_sub_dict(d1, d2):
    for key in d1.keys():
        if (key not in d2) or (not d1[key] == d2[key]):
            return False
    return True


class PermissionDescription(AuthzDescription):
    c_param = AuthzDescription.c_param.copy()
    c_param.update({
        'entity': SINGLE_REQUIRED_STRING,
        "exp": SINGLE_OPTIONAL_INT,
    })


class MemPermDescDB(object):
    """
    Expects one PermDescDB per resource owner
    """

    def __init__(self):
        self.db = {}

    def __getitem__(self, iid):
        return self.db[iid]

    def store(self, item):
        """
        Insert an item, if the _id already exists in the DB overwrite that
        item

        :param item: PermissionDescription instance
        """
        if '_id' in item:
            _id = item['_id']
            try:
                old_item = self[_id]
            except KeyError:
                if '_rev' not in item:
                    item['_rev'] = 1
            else:
                _rev = old_item['_rev']
                item['_rev'] = _rev + 1
                del self.db[_id]

            self.db[_id] = item
        else:
            _id = rndstr(32)
            item['_id'] = _id
            item['_rev'] = 1
            self.db[_id] = item

        return _id

    def find_one(self, pattern):
        for item in self.db.values():
            if is_sub_dict(pattern, item):
                return item
        raise UnknownObject(pattern)

    def find(self, pattern=None):
        """
        Find permission descriptions given a permission pattern

        :param pattern: A dictionary representing a subset of a
            PermissionDescription
        :return: list of PermissionDescription instances
        """
        if pattern:
            res = []
            for item in self.db.values():
                if is_sub_dict(pattern, item):
                    res.append(item)
        else:
            res = list(self.db.values())

        return res

    def remove(self, item=None, pdid=0):
        """
        Delete an item. Expect either an permission description or
        and identifier for an permission description as input.

        :param item:
        :param pdid:
        :return:
        """
        if item:
            try:
                pdid = item['_id']
            except KeyError:
                pdid = 0

        if pdid:
            del self.db[pdid]

    def restart(self):
        self.db = []

    def read(self, **kwargs):
        pattern = dict([(p, kwargs[p]) for p in ['resource_set_id', 'entity']
                        if p in kwargs])

        return self.find(pattern)

    def match(self, **kwargs):
        """
        Check that a requested permission matches something that is in the
        database.

        :param resource_set_id: The identifier for the resource
        :param entity: Who has the permission
        :param scopes: The wanted scopes
        :return: True or False
        """

        result = self.read(**kwargs)

        if len(result) == 0:
            return False

        try:
            _scopes = set(kwargs['scopes'])
        except KeyError:
            return True
        else:
            # enough the one matches
            for res in result:
                if set(res['scoped']).issuperset(_scopes):
                    return True

        return False

    def delete(self, **kwargs):
        for desc in self.read(**kwargs):
            self.remove(desc)

    def list(self):
        return [item["_id"] for item in self.find()]


class AuthzDB(object):
    def __init__(self):
        self.db = {}
        self.db_cls = MemPermDescDB

    def get_db(self, owner, requestor):
        _id = '{}:{}'.format(owner, requestor)
        try:
            return self.db[_id]
        except KeyError:
            self.db[_id] = self.db_cls()
            return self.db[_id]

    def add(self, owner, requestor, perm_desc):
        return self.get_db(owner, requestor).store(perm_desc)

    def match(self, owner, requestor, **kwargs):
        return self.get_db(owner, requestor).match(**kwargs)

    def delete(self, owner, requestor, item=None, pdid=0):
        self.get_db(owner, requestor).remover(item, pdid)

    def list(self, owner, requestor):
        return self.get_db(owner, requestor).list()
