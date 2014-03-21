import urllib
from mako.lookup import TemplateLookup
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.client import BearerHeader
from oic.oauth2.message import ErrorResponse

from uma import PAT
from uma.keyjar import init_keyjar
from uma.message import ResourceSetDescription
from uma.resourcesrv import ResourceServer1C
from uma.uma_info_provider import UMAInformationProvider

__author__ = 'roland'

KEYS = {
    "RSA": {
        "key": "as.key",
        "usage": ["enc", "sig"]
    }
}

USERDB = {
    "hans": {
        "displayName": "Hans Granberg",
        "givenName": "Hans",
        "sn": "Granberg",
        "eduPersonNickname": "Hasse",
        "email": "hans@example.org",
    },
    "linda": {
        "displayName": "Linda Lindgren",
        "eduPersonNickname": "Linda",
        "givenName": "Linda",
        "sn": "Lindgren",
        "email": "linda@example.com",
        "uid": "linda"
    }
}

# BUNDLES = {
#     "name": ["givenName", "displayName", "sn", "initials",
#              "eduPersonNickname"],
#     "static_org_info": ["c", "o", "co"],
#     "other": ["eduPersonPrincipalName", "eduPersonScopedAffiliation", "mail"],
#     "address": ["l", "streetAddress", "stateOrProvinceName",
#                 "postOfficeBox", "postalCode", "postalAddress",
#                 "co"]
# }
#
#
# def build_description_bundles(uid, info):
#     """
#     :param uid: The entity identifier
#     :param info: A dictionary with information about the entity
#     :return: A resource set description
#     """
#     singles = info.keys()
#     desc = ResourceSetDescription(
#         name=uid, scope=["http://its.umu.se/uma/actions/read"])
#     for name, collection in BUNDLES.items():
#         bundle = None
#         for attr in collection:
#             if attr in info:
#                 try:
#                     singles.remove(attr)
#                 except AttributeError:
#                     pass
#                 res = ResourceSetDescription(
#                     name="%s:%s" % (uid, attr),
#                     scope=["http://its.umu.se/uma/actions/read"])
#                 if not bundle:
#                     bundle = ResourceSetDescription(
#                         name="%s:%s" % (uid, name),
#                         scope=["http://its.umu.se/uma/actions/read"])
#                     try:
#                         desc["member"].append(bundle)
#                     except KeyError:
#                         desc["member"] = bundle
#                 try:
#                     bundle["member"].append(res)
#                 except KeyError:
#                     bundle["member"] = res
#     return desc


# {"scopes": [
#   "http://its.umu.se/uma/attr",
#   "http://its.umu.se/uma/attr/displayName",
#   "http://its.umu.se/uma/attr/displayName/Linda%20Lindgren",
#   "http://its.umu.se/uma/attr/uid",
#   "http://its.umu.se/uma/attr/uid/linda",
#   "http://its.umu.se/uma/attr/eduPersonNickname",
#   "http://its.umu.se/uma/attr/eduPersonNickname/Linda",
#   "http://its.umu.se/uma/attr/givenName",
#   "http://its.umu.se/uma/attr/givenName/Linda",
#   "http://its.umu.se/uma/attr/email",
#   "http://its.umu.se/uma/attr/email/linda%40example.com",
#   "http://its.umu.se/uma/attr/sn",
#   "http://its.umu.se/uma/attr/sn/Lindgren"]

DESC_BASE = "http://its.umu.se/uma/attr"
LEN_DESC_BASE = len(DESC_BASE)+1

READ = "http://its.umu.se/uma/op/read"
IDM = "http://its.umu.se/idm/"

ROOT = "./"

LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')


class UserInfo(UMAInformationProvider):
    def __init__(self, db, base):
        UMAInformationProvider.__init__(self)
        self.db = db
        self.base = base

    def __getitem__(self, item):
        return self.db[item]

    @staticmethod
    def create_scopes(info):
        scopes = [DESC_BASE]  # ALL
        for attr, val in info.items():
            scopes.append("%s/%s" % (DESC_BASE, attr))
            if isinstance(val, basestring):
                scopes.append("%s/%s/%s" % (DESC_BASE, attr, urllib.quote(val)))
            else:
                for v in val:
                    scopes.append("%s/%s/%s" % (DESC_BASE, attr,
                                                urllib.quote(v)))
        return scopes

    def build_resource_set_description(self, user):
        """
        Will return a list of ResourceSetDescriptions covering all
        resource sets.

        :param user: Who's resources to describe
        :return: list ResourceSetDescription instances
        """
        _scopes = self.create_scopes(self.db[user])
        rsd = ResourceSetDescription(scopes=_scopes, name=user)
        return [rsd]

    def do_get(self, uid, query=None):
        """
        GET /{uid}?*(['_attr_' '=' val]/[attr '=' val])
        """

        try:
            _ava = self.db[uid]
            if not query:
                return _ava

            _res = {}
            for key, vals in query.items():
                if key == "_attr_":
                    for attr in vals:
                        try:
                            _res[attr] = _ava[attr]
                        except KeyError:
                            pass
                else:
                    for val in vals:
                        if val in _ava[key]:
                            try:
                                _res[key].append(val)
                            except KeyError:
                                _res[key] = [val]
            return _res
        except KeyError:
            return ErrorResponse(error="not_available")

    def do(self, path, environ, permissions=None, requestor="", **kwargs):
        """
        :param path:
        :param environ: WSGI Environment
        :param permissions: A IntrospectionResponse containing permissions
        :param requestor: Who wants this.
        :return: Information
        """
        method = environ["REQUEST_METHOD"]
        try:
            query = environ["QUERY_STRING"]
        except KeyError:
            query = None

        if method == "GET":
            ava = self.do_get(path, query)
            _res = {}
            # pick out whatever is allowed to return
            for scope in self.create_scopes(ava):
                if self.filter_by_permission(permissions, scope):
                    if scope == DESC_BASE:
                        return ava
                    else:
                        part = scope[LEN_DESC_BASE:].split("/")
                        if len(part) == 1:
                            _res[part[0]] = ava[part[0]]
                        else:
                            try:
                                _res[part[0]].append(part[1])
                            except KeyError:
                                _res[part[0]] = [part[1]]
            return _res
        else:
            return ErrorResponse(error="unsupported_method")

    @staticmethod
    def get_necessary_scope(environ):
        return READ


class UserInfoMulti(UserInfo):
    def __init__(self, db, base):
        UserInfo.__init__(self, db, base)
        self.map_path2rsid = {}

    def build_resource_set_description(self, user):
        """
        Will return a list of ResourceSetDescriptions covering all
        resource sets.

        :param user: Who's resources to describe
        :return: list of 2-tuples (path, ResourceSetDescription instance)
        """
        ava = self.db[user]
        rsd = []
        base_url = IDM + user

        for att, vals in ava.items():
            _sub = []
            if isinstance(vals, basestring):
                _name = "%s/%s/%s" % (base_url, att, urllib.quote(vals))
                _sub.append(
                    ResourceSetDescription(name=_name, scopes=[READ]).to_json())
            else:
                for val in vals:
                    _name = "%s/%s/%s" % (base_url, att, urllib.quote(val))
                    _sub.append(ResourceSetDescription(name=_name,
                                                       scopes=[READ]).to_json())

            _name = "%s/%s" % (base_url, att)
            rsd.append(ResourceSetDescription(name=_name, scopes=[READ],
                                              subsets=_sub).to_json())

        return [ResourceSetDescription(name=base_url, scopes=[READ],
                                       subsets=rsd)]

    @staticmethod
    def _filter_by_permission(base, ava, response, name2rsid):
        """
        :param ava: attribute value dictionary
        :param response: A IntrospectionResponse containing permissions
        :param path2rsid: A map from paths to RSIDs
        """
        base_url = IDM + base

        # a bit simplistic since neither expired_at or scopes are checked
        allowed = [a["resource_set_id"] for a in response["permissions"]]

        res = {}
        for att, vals in ava.items():
            _path = "%s/%s" % (base_url, att)
            if name2rsid[_path] in allowed:
                res[att] = vals
                continue

            if isinstance(vals, basestring):
                _path = "%s/%s/%s" % (base_url, att, urllib.quote(vals))
                if name2rsid[_path] in allowed:
                    res[att] = vals
            else:
                for val in vals:
                    _path = "%s/%s/%s" % (base_url, att, urllib.quote(val))
                    if name2rsid[_path] in allowed:
                        try:
                            res[att].append(val)
                        except KeyError:
                            res[att] = [val]

            _name = "%s/%s" % (base_url, att)
        return res

    def do(self, path, environ, response=None, requestor="", **kwargs):
        """
        :param path:
        :param environ: WSGI Environment
        :param response: A IntrospectionResponse containing permissions
        :param requestor: Who wants this.
        :return: Information
        """
        method = environ["REQUEST_METHOD"]
        try:
            query = environ["QUERY_STRING"]
        except KeyError:
            query = None

        if method == "GET":
            ava = self.do_get(path, query)
            # pick out whatever is allowed to return
            return self._filter_by_permission(path, ava, response,
                                              kwargs["name2rsid"])
        else:
            return ErrorResponse(error="unsupported_method")


def main(baseurl, cookie_handler):

    config = {
        "registration_info": {
            "token_endpoint_auth_method": "client_secret_basic",
            "application_type": "web",
            "redirect_uris": ["%s/uma" % baseurl],
            "grant_types": ["authorization_code", "implicit"],
            "scope": [PAT],
            "response_types": ["code", "token"]
        },
        "client_authn_method": {
            "client_secret_basic": ClientSecretBasic,
            "bearer_header": BearerHeader
        },
        "flow_type": "code",
        "symkey": "abcdefghijklmnop",
        "baseurl": baseurl,
        "scope": PAT
    }

    dataset = UserInfoMulti(USERDB, "")
    res_srv = ResourceServer1C(dataset, **config)

    init_keyjar(res_srv, KEYS, "static/jwk_rs.json")
    cookie_handler.init_srv(res_srv)

    return res_srv