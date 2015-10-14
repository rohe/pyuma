import logging
import traceback

from six.moves.urllib.parse import urlencode

from oic.oauth2.util import JSON_ENCODED
from oic.oauth2.provider import Endpoint
from oic.utils import http_util
from oic.utils.http_util import Response
from oic.utils.time_util import utc_time_sans_frac
from uma.client import Client
from uma.message import IntrospectionRequest
from uma.message import ResourceSetResponse
from uma.message import IntrospectionResponse
from uma.message import ResourceSetDescription
from uma.message import StatusResponse
from src.uma.authzsrv import RSR_PATH

logger = logging.getLogger(__name__)

__author__ = 'rolandh'


class Unknown(Exception):
    pass


class UnknownAuthzSrv(Exception):
    pass


def client_init(ca_certs, client_authn_method, config):
    _client = Client(ca_certs=ca_certs,
                     client_authn_methods=client_authn_method)
    for param in ["client_id", "client_secret", "redirect_uris",
                  "authorization_endpoint", "token_endpoint",
                  "token_revocation_endpoint"]:
        try:
            setattr(_client, param, config[param])
        except KeyError:
            pass

    return _client


class PermissionRegistry(object):
    """
    A database over what resource set descriptions the server has registered
    """

    def __init__(self):
        self.db = {}

    def set(self, owner, key, value):
        try:
            self.db[owner][key] = value
        except KeyError:
            self.db[owner] = {key: value}

    def get(self, owner, item):
        try:
            return self.db[owner][item]
        except KeyError:
            if owner not in self.db:
                raise Unknown(owner)
            else:
                raise

    def add_resource_set_description(self, owner, item):
        try:
            self.db[owner]["resource_set"] = [item]
        except KeyError:
            self.db[owner] = {"resource_set": [item]}

    def get_resource_set_description(self, owner, name):
        for rsd in self.db[owner]["resource_set"]:
            if rsd["name"] == name:
                return rsd

        return None


REQUEST2ENDPOINT = {
    "IntrospectionRequest": "introspection_endpoint",
    "ResourceSetDescription": "resource_set_registration_endpoint",
    "PermissionRegistrationRequest": "permission_registration_endpoint",
}

DEFAULT_METHOD = "POST"


def create_query(srv, uid, attr=None):
    url = "%s/info/%s" % (srv, uid)
    if attr:
        url += "&%s" % urlencode([("attr", v) for v in attr])

    return url


def parse_query(path):
    """
    :param path: The HTTP path
        Should be of the form /info/<uid>
    """
    return path[6:].replace("--", "@")


class DataSetEndpoint(Endpoint):
    etype = "dataset_endpoint"




class ResourceServer():
    def __init__(self, dataset, resource_owner, symkey="", client_id=None,
                 ca_certs=None, client_authn_methods=None, keyjar=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope="",
                 **kwargs):
        self.client = Client.__init__(client_id, ca_certs, client_authn_methods,
                                      keyjar, server_info, authz_page,
                                      flow_type, password, registration_info,
                                      response_type, scope)
        self.rs_handler = ResourceSetHandler(dataset, self.client,
                                             resource_owner)
        self.symkey = symkey
        self.kwargs = kwargs
        self.srv_discovery_url = ""
        self.cookie_handler = http_util.CookieDealer(self)
        self.cookie_name = "resourceserver"
        self.rsd_map = {}
        self.pat = None

    def rs_request_info(self, owner, msgtype, method=DEFAULT_METHOD,
                        authn_method="bearer_header", request_args=None,
                        extra_args=None):

        return self.client.request_info(msgtype, method,
                                        request_args=request_args,
                                        extra_args=extra_args,
                                        authn_method=authn_method,
                                        content_type=JSON_ENCODED)

    @staticmethod
    def _get_bearer_token(authz):
        try:
            if authz.startswith("Bearer"):
                return authz[len("Bearer "):]
            else:
                return None
        except KeyError:
            return None

    def do_introspection(self, rpt, path=None):
        """
        The resource server doing introspection on a RPT at the AuthzServer

        :param rpt: Resource access token
        :param path: path representing the resource
        :returns:
        """

        pat = self.client.token
        ir = IntrospectionRequest(token=rpt)

        # if path:
        #     fpath = self.rs_handler.dataset.resource_name(path)
        #     ir["resource_id"] = self.rs_handler.path2rsid[fpath]

        request_args = {"access_token": pat}
        ht_args = self.client.client_authn_method[
            "bearer_header"](self).construct(ir, request_args=request_args)

        url = list(self.client.provider_info.values())[0][
            "introspection_endpoint"]

        return self.client.request_and_return(url, IntrospectionResponse,
                                              body=ir.to_json(),
                                              body_type="json",
                                              http_args=ht_args)

    # ========================================================================
    # Below is the client API methods
    # ========================================================================
    def result(self, environ, start_response, result):
        resp = Response(mako_template="opresult.mako",
                        template_lookup=self.kwargs["template_lookup"],
                        headers=[])
        argv = {
            "result": result
        }
        return resp(environ, start_response, **argv)

    @staticmethod
    def filter_by_permission(intro, scope=None):
        """
        :param intro: An IntrospectionResponse instance
        :param scope: The scope that access is asked for
        :return: list of resource_set_description ids
        :rtype: list
        """

        rsids = []
        now = utc_time_sans_frac()
        try:
            assert now < intro["exp"]
        except KeyError:
            pass
        except AssertionError:
            return False

        for perm in intro["permissions"]:
            try:
                assert now < perm["exp"]
            except KeyError:
                pass
            except AssertionError:
                continue

            try:
                assert scope in perm["scopes"]
            except AssertionError:
                pass
            else:
                rsids.append(perm["resource_set_id"])

        return rsids

    def collect_info(self, introspection_response, scope):
        """
        :param introspection_response:
        :param scope:
        :return: Dictionary of attributes and values
        :rtype: dict
        """
        rsids = self.filter_by_permission(introspection_response, scope)

        # Collect information
        res = {}
        for rsid in rsids:
            lid = self.rs_handler.rsid2lid[rsid]
            part = lid.split(':')
            if len(part) == 2:  # every value for an attribute
                res[part[1]] = self.rs_handler.get_info(part[0], part[1])
            else:
                try:
                    res[part[1]].append(part[2])
                except KeyError:
                    res[part[1]] = [part[2]]

        return res

    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------------
    def resource_endpoint(self, operation, path, auth=None, query=None):
        """
        This is where the client sends its requests.
        Assumes a HTTP interface.

        Three possible cases:
        - No RPT
        - A RPT that doesn't give the necessary access
        - A valid RPT

        :param auth: Authentication information, HTTP Authorization header
        :param operation: A HTTP operation: "GET","POST", ...
        :param path: The URL path
        :param query: A possible URL query part
        :return: HTTP response
        """

        rpt = self._get_bearer_token(auth)
        if auth is None:  # no RPT
            rssp = self.rs_handler.query2permission_registration_request_primer(
                operation, path, query)
        else:
            self.do_introspection(rpt)

        return Response
