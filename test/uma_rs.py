import copy
import urllib
from mako.lookup import TemplateLookup
from oic.utils.userinfo import UserInfo
from uma import init_keyjar
from uma.client import UMA_SCOPE
from uma.message import ResourceSetDescription
from uma.resourcesrv import ResourceServer, DESC_BASE

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

RES_SRV = None
RP = None


class IdmUserInfo(UserInfo):
    """ Read only interface to a user info store """

    @staticmethod
    def _filtering(userinfo, authzdesc=None):
        """
        Return only those claims that are asked for.
        It's a best effort task; if essential claims are not present
        no error is flagged.

        :param userinfo: A dictionary containing the available user info.
        :param authzdesc: A list of Authz descriptions
        :return: A dictionary of attribute values
        """

        if authzdesc is None:
            return copy.copy(userinfo)
        else:
            ld = len(DESC_BASE)
            rel_scopes = []
            for ad in authzdesc:
                rel_scopes.extend([s[ld:] for s in ad["scopes"]])

            _scopes = []
            for scop in rel_scopes:
                if scop.startswith("/"):
                    _scopes.append(scop[1:])
                else:
                    _scopes.append(scop)

            if "" in _scopes:  # Anything match
                return copy.copy(userinfo)
            else:
                result = {}
                for attr, val in userinfo.items():
                    if attr in _scopes:
                        result[attr] = val
                    else:
                        _val = []
                        if isinstance(val, basestring):
                            ava = "%s/%s" % (attr, urllib.quote(val))
                            if ava in rel_scopes:
                                _val.append(val)
                        else:
                            for v in val:
                                ava = "%s/%s" % (attr, urllib.quote(v))
                                if ava in rel_scopes:
                                    _val.append(v)
                        if _val:
                            result[attr] = _val

            return result

    def __call__(self, userid, authzdesc=None, **kwargs):
        try:
            return self._filtering(self.db[userid], authzdesc)
        except KeyError:
            return {}


def build_description(uid, info):
    """
    :param uid: The entity identifier
    :param info: A dictionary with information about the entity
    :return: A resource set description
    """
    scopes = [DESC_BASE]  # ALL
    for attr, val in info.items():
        scopes.append("%s/%s" % (DESC_BASE, attr))
        if isinstance(val, basestring):
            scopes.append("%s/%s/%s" % (DESC_BASE, attr, urllib.quote(val)))
        else:
            for v in val:
                scopes.append("%s/%s/%s" % (DESC_BASE, attr, urllib.quote(v)))

    desc = ResourceSetDescription(name=uid, scopes=scopes)
    return desc


LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')


def main(host, cookie_handler):
    config = {
        "scope": [UMA_SCOPE["PAT"], "openid"],
        "base_url": host,
        "registration_info": {
            "client_name": host,
            "application_type": "web",
            "redirect_uris": ["%s/uma" % host]
        },
        "template_lookup": LOOKUP,
    }

    res_srv = ResourceServer(IdmUserInfo(USERDB), config, baseurl=host)
    init_keyjar(res_srv, KEYS, "static/jwk_rs.json")
    cookie_handler.init_srv(res_srv)

    return res_srv