import logging
import urllib
from oic.oic import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect
from oic.utils.http_util import R2C
#from oic.utils.userinfo import UserInfo
from saml2.userinfo import UserInfo as SAMLUserInfo
from uma import UMAError

from uma.client import Client
from uma.message import PermissionRegistrationResponse
from uma.resourcesrv import create_query

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


class UMAUserInfo(SAMLUserInfo):
    def __init__(self, client_name, redirect_uris, resource_srv):
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
            resp = self.client.acquire_grant(as_uri, "RPT", sp_user, state)
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
