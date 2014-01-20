import copy
import logging
import urllib

from oic.oic import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect
from oic.utils.http_util import R2C
from oic.utils.userinfo import UserInfo
from oic.utils.aes import encrypt

from saml2.userinfo import UserInfo as SAMLUserInfo

from uma import UMAError
from uma.client import Client
from uma.message import PermissionRegistrationResponse
from uma.resourcesrv import create_query
from uma.resourcesrv import DESC_BASE

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


class UMAUserInfo(SAMLUserInfo):
    def __init__(self, client_name, redirect_uris, resource_srv, acr):
        SAMLUserInfo.__init__(self)

        # The UMA Client
        reginfo = {
            "client_name": client_name,
            "application_type": "native",
            "redirect_uris": redirect_uris
        }

        cconf = {"client_authn_method": CLIENT_AUTHN_METHOD}
        self.client = Client({}, cconf, registration_info=reginfo)
        self.client.redirect_uris = redirect_uris
        self.resource_srv = resource_srv
        self.acr = acr

    def __call__(self, user, attrs=None, state=""):
        """
        :param user: user name of the form <user>%40<domain>
        :param attrs: which attributes to return
        """
        return self.get_info(user, attrs, state)

    def rs_query(self, sp_user, user, attr=None):
        try:
            rpt = self.client.token[sp_user]["RPT"]
        except KeyError:
            rpt = None

        url = create_query(self.resource_srv, urllib.quote(user), attr)

        if rpt:
            kwargs = {"headers": [("Authorization", "Bearer %s" % rpt)]}
        else:
            kwargs = {}

        return self.client.send(url, "GET", **kwargs)

    def get_info(self, user, attr=None, state=""):
        """

        :param user: user = <uid>%40<domain>%40<sp_entityid>
        :param attr: A list of wanted attributes
        """
        sp_user = urllib.unquote(user)
        uad = sp_user.rsplit("@",1)[0]
        resp = self.rs_query(sp_user, uad, attr)

        if resp.status_code == 200:
            return Response(resp.text)

        if resp.status_code == 401:  # No RPT
            as_uri = resp.headers["as_uri"]
            resp = self.client.acquire_grant(as_uri, "RPT", sp_user, state,
                                             self.acr)
            if resp.status_code == 302:  # which it should be
                headers = [(a, b) for a, b in resp.headers.items()
                           if a != "location"]
                return Redirect(resp.headers["location"], headers=headers)
            elif resp.status_code == 200:  # ???
                return Response(resp.text)
            else:
                return R2C[resp.status_code](resp.text)

        if resp.status_code == 403:  # Permission registered, got ticket
            prr = PermissionRegistrationResponse().from_json(resp.text)
            resp = self.client.authorization_data_request(sp_user,
                                                          prr["ticket"])
            if resp.status_code == 200:
                return self.get_info(user, attr)

        raise UMAError()

    def get_tokens(self, query):
        aresp = AuthorizationResponse().from_urlencoded(query)
        uid = self.client.acquire_access_token(aresp, "AAT")
        self.client.get_rpt(uid)
        return uid


class IdmUserInfo(UserInfo):
    """ Read only interface to a user info store """
    def __init__(self, db, gpii_url, symkey):
        UserInfo.__init__(self, db)
        self.gpii_url = gpii_url
        self.symkey = symkey

    def identity(self, userid, sp_entity_id=""):
        _ident = copy.copy(self.db[userid])
        msg = "{'aud':%s, 'sub':%s}" % (sp_entity_id, userid)
        token = encrypt(self.symkey, msg)
        _ident["gpii"] = "%s/%s/%s" % (self.gpii_url, userid, token)

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
            return self._filtering(self.identity(userid), authzdesc)
        except KeyError:
            return {}

