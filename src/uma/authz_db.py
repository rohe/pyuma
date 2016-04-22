from oic import rndstr
from oic.oauth2 import SINGLE_OPTIONAL_INT
from oic.oauth2 import SINGLE_OPTIONAL_STRING

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
        "exp": SINGLE_OPTIONAL_INT,
        'require': SINGLE_OPTIONAL_STRING
    })


class MemPermDescDB(object):
    """
    Expects one PermDescDB per resource owner
    """

    def __init__(self):
        self.db = {}

    def __getitem__(self, iid):
        return self.db[iid]

    def __contains__(self, iid):
        return iid in self.db

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

    def remove(self, item=None, pid=0):
        """
        Delete an item. Expect either an permission description or
        and identifier for an permission description as input.

        :param item:
        :param pid:
        :return:
        """
        if item:
            try:
                pid = item['_id']
            except KeyError:
                pid = 0

        if pid:
            del self.db[pid]

    def restart(self):
        self.db = []

    def read(self, **kwargs):
        pattern = dict([(p, kwargs[p]) for p in ['resource_set_id']
                        if p in kwargs])

        return self.find(pattern)

    def require_match(self, require, given):
        for key, val in require.items():
            try:
                if given[key] != val:
                    return False
            except KeyError:
                return False
        return True

    def match(self, identity=None, **kwargs):
        """
        Check that a requested permission matches something that is in the
        database.

        :param info: Information about the entity that wants the permission
        :param kwargs: keyword arguments to build the filter from
        :return: The id of the matching authz decision
        """
        if identity is None:
            identity = {}

        result = self.read(**kwargs)

        if len(result) == 0:
            return []

        _res = []
        for r in result:
            if 'require' in r:
                if self.require_match(r['require'], identity):
                    _res.append(r)
            else:
                _res.append(r)
        result = _res

        if len(result) == 0:
            return []

        try:
            _scopes = set(kwargs['scopes'])
        except KeyError:
            return [r['_id'] for r in result]
        else:
            return [r['_id'] for r in result if
                    set(r['scopes']).issuperset(_scopes)]

    def delete(self, **kwargs):
        for desc in self.read(**kwargs):
            self.remove(desc)

    def list(self):
        return [item["_id"] for item in self.find()]


class AuthzDB(object):
    def __init__(self):
        self.db = {}
        self.db_cls = MemPermDescDB

    def get_db(self, owner):
        _id = owner
        try:
            return self.db[_id]
        except KeyError:
            self.db[_id] = self.db_cls()
            return self.db[_id]

    def add(self, owner, perm_desc):
        return self.get_db(owner).store(perm_desc)

    def match(self, owner, identity=None, **kwargs):
        return self.get_db(owner).match(identity, **kwargs)

    def delete(self, owner, item=None, pid=0):
        self.get_db(owner).remove(item, pid)

    def read(self, owner, pid):
        return self.get_db(owner)[pid]

    def list(self, owner):
        return self.get_db(owner).list()
