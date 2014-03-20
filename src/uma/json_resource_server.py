import json
from urlparse import parse_qs
from oic.oauth2.message import ErrorResponse
from oic.utils.http_util import Response
from oic.utils.http_util import NoContent
from oic.utils.http_util import get_post
from oic.utils.time_util import utc_time_sans_frac
from uma.message import ResourceSetDescription
from uma.uma_info_provider import UMAInformationProvider

__author__ = 'roland'
import os

DEF_SCOPES = [
    "http://dirg.org.umu.se/uma/scopes/read",
    "http://dirg.org.umu.se/uma/scopes/create",
    "http://dirg.org.umu.se/uma/scopes/delete",
    "http://dirg.org.umu.se/uma/scopes/modify",
    "http://dirg.org.umu.se/uma/scopes/patch",
    "http://dirg.org.umu.se/uma/scopes/query",
]

OPER2SCOPE = {
    "GET": "http://dirg.org.umu.se/uma/scopes/read",
    "POST": "http://dirg.org.umu.se/uma/scopes/create",
    "PUT": "http://dirg.org.umu.se/uma/scopes/modify",
    "DELETE": "http://dirg.org.umu.se/uma/scopes/delete",
    "PATCH": "http://dirg.org.umu.se/uma/scopes/patch",
    "QUERY": "http://dirg.org.umu.se/uma/scopes/query"
}


class JsonResourceServer(UMAInformationProvider):
    def __init__(self, root, base, baseurl, owners=None):
        UMAInformationProvider.__init__(self)
        if not os.path.isdir(root):
            os.mkdir(root)
        self.root = root
        self.base = base

        if baseurl.endswith("/"):
            baseurl = baseurl[:-1]

        self.baseurl = baseurl  # This is the http://domain:port part
        self.index = {}  # keys are owners, values are resource index
        if owners:
            for owner in owners:
                self.index[owner] = self.get_index(owner)

    def get_index(self, owner):
        _path = os.path.join(self.root, owner)
        i = 0
        if os.path.exists(_path):
            for _p in os.listdir(_path):
                if int(_p) > i:
                    i = int(_p)
        else:
            os.mkdir(_path)
        return i

    def resource_name(self, path):
        """
        Convert path to file name
        urlpath = <base>/dir1/dir2/file
        filepath = <root>/dir1/dir2/file
        """
        return path.replace(self.base, self.root, 1)

    def url(self, name):
        """ Convert file name to path """

        return name.replace(self.root, self.base, 1)

    @staticmethod
    def check_permission(authzdesc, oper):
        """
        :param authzdesc: An AuthzDescription instance
        :param oper: The operation (HTTP method)
        """
        now = utc_time_sans_frac()
        try:
            assert now < authzdesc["expires_at"]
        except KeyError:
            pass
        except AssertionError:
            return False

        for perm in authzdesc["permissions"]:
            try:
                assert now < perm["expires_at"]
            except KeyError:
                pass
            except AssertionError:
                return False

            try:
                assert OPER2SCOPE[oper] in perm["scopes"]
            except AssertionError:
                pass
            else:
                return True

        return False

    def do_get(self, path):
        """
        GET /{collection}/{id}
        """

        _name = self.resource_name(path)
        if os.path.isfile(_name):
            try:
                data = open(_name, "r").read()
            except IOError:
                return ErrorResponse(error="not_available")
            else:
                return Response(data)
        else:
            return ErrorResponse(error="not_allowed")

    def do_query(self, path, query):
        """

        """
        _name = self.resource_name(path)
        try:
            assert os.path.exists(_name)
            assert os.path.isdir(_name)
        except AssertionError:
            ErrorResponse(error="not_allowed")

        _filt = parse_qs(query)
        res = []

        for _p in os.listdir(path):
            if os.path.isfile(_p):
                try:
                    data = open(_p, "r").read()
                except IOError:
                    pass
                else:
                    _j = json.loads(data)
                    match = True
                    for key, vals in _filt.items():
                        if not match:
                            break
                        for val in vals:
                            try:
                                assert val in _j[key]
                            except (AssertionError, KeyError):
                                match = False
                                break
                    if match:
                        res.append(_j)

        return Response(json.dumps(res))

    def do_delete(self, path):
        """
        DELETE /{collection}/{id}
        """

        if os.path.exists(self.resource_name(path)):
            os.remove(self.resource_name(path))
            return NoContent("")
        else:
            return ErrorResponse(error="not_available")

    def do_put(self, path, info):
        """
        UPDATE: PUT /{collection}/{id}

        """

        _name = self.resource_name(path)
        try:
            f = open(_name, "w")
        except IOError:
            return ErrorResponse(error="not_allowed")

        head, tail = os.path.split(_name)

        try:
            _ji = json.loads(info)
        except ValueError:
            return ErrorResponse(error="not_json")

        try:
            assert _ji["_id"] == tail
        except KeyError:
            _ji["_id"] = tail
        except AssertionError:
            return ErrorResponse(error="not_allowed")

        f.write(json.dumps(_ji))
        f.close()
        return Response(json.dumps({"_id": tail}),
                        headers=[("Location", "%s/%s" % (self.baseurl,
                                                         self.url(_name)))])

    def do_patch(self, path, info):
        """
        UPDATE: PATCH /{collection}/{id}

        """

        _name = self.resource_name(path)
        try:
            f = open(_name, "r")
        except IOError:
            return ErrorResponse(error="not_allowed")

        head, tail = os.path.split(_name)

        try:
            _ji = json.loads(info)
        except ValueError:
            return ErrorResponse(error="not_json")

        try:
            assert _ji["_id"] == tail
        except KeyError:
            pass
        except AssertionError:
            return ErrorResponse(error="not_allowed")

        _stored = json.loads(f.read())
        _stored.update(_ji)
        f.close()
        try:
            f = open(_name, "w")
        except IOError:
            return ErrorResponse(error="not_allowed")
        f.write(json.dumps(_stored))
        f.close()
        return Response(json.dumps({"_id": tail}),
                        headers=[("Location", "%s/%s" % (self.baseurl,
                                                         self.url(_name)))])

    def do_post(self, path, info, user):
        """
        POST /{collection}
        """

        _name = self.resource_name(path)
        try:
            index = self.index[user]
        except KeyError:
            index = 1
            self.index[user] = 1
        else:
            index += 1
            self.index[user] = index

        _name += "/%d" % index

        try:
            _ji = json.loads(info)
        except ValueError:
            return ErrorResponse(error="not_json")

        try:
            f = open(_name, "w")
        except IOError, err:
            head, tail = os.path.split(_name)
            # try to create
            os.mkdir(head)
            try:
                f = open(_name, "w")
            except IOError:
                return ErrorResponse(error="not_allowed")

        _ji["_id"] = index
        f.write(json.dumps(_ji))
        f.close()

        return Response(json.dumps({"_id": index}),
                        headers=[("Location", "%s/%s" % (self.baseurl,
                                                         self.url(_name)))])

    def do(self, path, environ, permission=None, user=""):
        """

        """
        method = environ["REQUEST_METHOD"]

        if method == "GET":
            if "QUERY_STRING" in environ and environ["QUERY_STRING"]:
                method = "QUERY"

        # Verify that the permission is sufficient
        allowed = False
        if user:
            _pat = "%s%s" % (self.base, user)
            if path.startswith(_pat) or path == _pat:
                allowed = True
        elif permission and self.check_permission(permission, method):
            allowed = True

        if not allowed:
            return ErrorResponse(error="Unauthorized")

        if method in ["PUT", "POST", "PATCH"]:
            info = get_post(environ)
        else:
            info = ""

        if method == "GET":
            return self.do_get(path)
        elif method == "QUERY":
            return self.do_query(path, environ["QUERY_STRING"])
        elif method == "DELETE":
            return self.do_delete(path)
        elif method == "PUT":
            return self.do_put(path, info)
        elif method == "POST":
            return self.do_post(path, info, user)
        elif method == "PATCH":
            return self.do_patch(path, info)
        else:
            return ErrorResponse(error="unsupported_method")

    def get_owner(self, path):
        part = []
        while path:
            head, tail = os.path.split(path)
            if not tail:
                part.append(head)
                break
            else:
                part.append(tail)
                path = head

        part.reverse()
        if part[1] in self.index:
            return part[1]
        else:
            return None

    def build_resource_set_description(self, user):
        """
        Will return a list of ResourceSetDescriptions covering all
        resource sets.

        :param user: Who's resources to describe
        :return: list of 2-tuples (path, ResourceSetDescription instance)
        """
        rsd = []
        path = "%s/%s" % (self.root, user)
        for _p in os.listdir(path):
            _pname = os.path.join(path, _p)
            rsd.append((_pname,
                        ResourceSetDescription(name=self.url(_pname),
                                               scopes=DEF_SCOPES)))

        return rsd

    def update_resource_set_description(self, user):
        """
        :param user: The owner of the resource sets
        :return: A list of 2-tuples (changetype, change)
            changetype = ["add", "update", "delete"]
        """
        pass

    @staticmethod
    def get_necessary_scope(environ):
        return OPER2SCOPE[environ["REQUEST_METHOD"]]