import logging
import urllib

from oic.oic import AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect
from oic.utils.http_util import R2C

from saml2.userinfo import UserInfo as SAMLUserInfo

from uma import UMAError
from uma.client import Client
from uma.message import PermissionRegistrationResponse
from uma.resourcesrv import create_query

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


# the API to the UMA protected IDP system that the IdP uses

class UMAUserInfo(SAMLUserInfo):
    def __init__(self, client_name, redirect_uris, resource_srv, acr,
                 verify_ssl=True):
        SAMLUserInfo.__init__(self)

        # The UMA Client
        reginfo = {
            "client_name": client_name,
            "application_type": "native",
            "redirect_uris": redirect_uris
        }

        self.client = Client(
            {}, client_authn_method=CLIENT_AUTHN_METHOD,
            registration_info=reginfo, verify_ssl=verify_ssl)

        self.client.redirect_uris = redirect_uris
        self.resource_srv = resource_srv
        self.acr = acr

    def __call__(self, user, requestor, attrs=None, state="", **kwargs):
        """
        This is the main API

        :param user: user identifier
        :param requestor: The entity_id of the SP that requests the information
        :param attrs: which attributes to return
        :param state: Where in the process am I
        """
        return self.get_info(user, requestor, attrs, state, **kwargs)

    def rs_query(self, sp_user, user, attr=None):
        """

        :param sp_user: an identifier representing the tuple (user, sp)
        :param user: user identifier common with the backend system
        """
        try:
            rpt = self.client.token[sp_user]["RPT"]
        except KeyError:
            rpt = None

        url = create_query(self.resource_srv, urllib.quote(user), attr)

        if rpt:
            kwargs = {"headers": {"Authorization": "Bearer %s" % rpt}}
        else:
            kwargs = {}

        return self.client.send(url, "GET", **kwargs)

    def get_info(self, user, requestor, attrs=None, state="", **kwargs):
        """

        :param user: user identifier
        :param requestor: The entity_id of the SP that requests the information
        :param attrs: which attributes to return
        :param state: Where in the process am I
        """

        # The real requestor is <user>@<sp_entity_id>
        user_and_sp = "%s@%s" % (user, requestor)
        resp = self.rs_query(user_and_sp, user, attrs)

        args = {}
        for attr in ["authn_method", "password"]:
            try:
                args[attr] = kwargs[attr]
            except KeyError:
                args[attr] = ""

        if resp.status_code == 200:
            return Response(resp.text)

        if resp.status_code == 401:  # No RPT
            as_uri = resp.headers["as_uri"]
            return self.client.acquire_grant(as_uri, "RPT", user_and_sp, state,
                                             self.acr, **args)
            #if isinstance(resp, Redirect):  # which it should be
                # redirect that are part of the grant code flow
            #    return resp
            # elif resp.status_code == 200:  # ???
            #     return Response(resp.text)
            # else:
            #     return R2C[resp.status_code](resp.text)

        if resp.status_code == 403:  # Permission registered, got ticket
            if state == "403":  # loop ?
                return {}
            prr = PermissionRegistrationResponse().from_json(resp.text)
            resp = self.client.authorization_data_request(user_and_sp,
                                                          prr["ticket"])
            if resp.status_code in (200, 201):
                return self.get_info(user, requestor, attrs, "403")

        raise UMAError()

    def get_tokens(self, query):
        aresp = AuthorizationResponse().from_urlencoded(query)
        uid = self.client.acquire_access_token(aresp, "AAT")
        self.client.get_rpt(uid)
        return uid
