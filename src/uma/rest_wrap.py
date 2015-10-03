from urllib.parse import parse_qs
from uma.db_wrap import DBWrap
from uma.message import ResourceSetDescription

__author__ = 'roland'

OP2SCOPE = {
    "GET": "https://dirg.org.umu.se/uma/get"
}


def _local_id(*args):
    return ":".join(args)


def path2uid(path):
    return path


def operation2scope(operation):
    return OP2SCOPE[operation]


class RESTIDMWarp(DBWrap):
    def __init__(self, db, **kwargs):
        DBWrap.__init__(self, db, list(OP2SCOPE.values()), **kwargs)
        self.base_url = kwargs["baseurl"]

    def _register(self, user, key, val=None, scopes=None, parent=None):
        if val:
            name = "{} {}={}".format(user, key, val)
            _id = _local_id(user, key, val)
        else:
            name = "{} {}".format(user, key)
            _id = _local_id(user, key)

        if scopes is None:
            scopes = self.scopes

        _rsd = ResourceSetDescription(scopes=scopes, name=name)
        self.lid2scopes[_id] = scopes
        if parent is not None:
            try:
                self.child_lid[parent].append(_id)
            except:
                self.child_lid[parent] = [_id]
        return _id, _rsd

    def build_resource_set_descriptions(self, filter, scopes=None):
        """
        Will return a list of ResourceSetDescriptions covering all
        resource sets.

        :param filter: A filter description as a dictionary
        :param scopes: List of scopes that can by applied to this resource
        :return: list of tuples of local id and ResourceSetDescription instances
        """
        user = filter["user"]
        rss = []
        for key, val in self.db[user].items():
            _parent, _rsd = self._register(user, key, scopes=scopes)
            #rss.append((_parent, _rsd))   -  Not needed

            if isinstance(val, list):
                for v in val:
                    rss.append(self._register(user, key, v, scopes, _parent))
            else:
                rss.append(self._register(user, key, val, scopes, _parent))

        return rss

    def query2local_id(self, path, query):
        """
        Typical query:

        attr=sn&ava=email:foo@example.com

        :param path: URL path - TODO deducting the base url path
        :param query: URL query part
        :return: list of leave (attribute value) local ids
        :rtype: list
        """

        qs = parse_qs(query)

        # path to uid
        uid = path2uid(path)
        _lids = []

        try:
            for attr in qs["attr"]:
                plid = _local_id(uid, attr)
                _lids.extend(self.child_lid[plid])
        except KeyError:
            pass

        try:
            items = qs["ava"]
        except KeyError:
            pass
        else:
            for ava in items:
                attr, val = ava.split(':', 1)
                _lids.append(_local_id(uid, attr, val))

        return _lids

    def query2permission_registration_request_primer(self, operation, path,
                                                     query):
        """
        :param operation: Which REST operation that is performed
        :param path: The URL path - TODO deducting the base url path
        :param query: The URL query
        :return: list of (lid, scope) tuples
        """
        scope = operation2scope(operation)
        return [(l, scope) for l in self.query2local_id(path, query) if
                scope in self.lid2scopes[l]]
