import json
import logging
from urllib.parse import urlencode

from oic.oauth2.provider import Endpoint
from oic.utils import http_util
from oic.utils.http_util import Response
from oic.utils.time_util import utc_time_sans_frac
from uma.message import IntrospectionRequest
from uma.message import PermissionRegistrationRequest
from uma.message import PermissionRegistrationResponse
from uma.message import IntrospectionResponse
from uma.resource_set import ResourceSetHandler

logger = logging.getLogger(__name__)

__author__ = 'rolandh'


class Unknown(Exception):
    pass


class UnknownAuthzSrv(Exception):
    pass


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


class ResourceEndpoint(Endpoint):
    etype = "resource_endpoint"


class ResourceServer(object):
    """
    One ResourceServer per resource_owner+dataset pair
    """
    def __init__(self, dataset, resource_owner, client, symkey="",
                 **kwargs):
        # self.client = Client(client_id=client_id, ca_certs=ca_certs,
        #                      client_authn_methods=client_authn_methods,
        #                      keyjar=keyjar, server_info=server_info,
        #                      authz_page=authz_page,
        #                      flow_type=flow_type, password=password,
        #                      registration_info=registration_info,
        #                      response_type=response_type, scope=scope)
        self.client = client
        self.rs_handler = ResourceSetHandler(dataset, self.client,
                                             resource_owner)
        self.resource_owner = resource_owner
        self.symkey = symkey
        self.kwargs = kwargs
        self.srv_discovery_url = ""
        self.cookie_handler = http_util.CookieDealer(self)
        self.cookie_name = "resource_server"
        self.rsd_map = {}
        self.pat = None
        self.keyjar = self.client.keyjar
        self.kid = {"sig": {}, "enc": {}}

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

        pat = self.client.token[self.resource_owner]['PAT']
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

    def create_permission_request(self, operation, uid, query):
        res_set = self.rs_handler.query2permission_registration_request_primer(
            operation, uid, query)

        pre_rpp = [(self.rs_handler.rsd_map[lid]['_id'], [scope]) for lid, scope
                   in res_set]

        prrs = []
        for rsid, scopes in pre_rpp:
            prrs.append(PermissionRegistrationRequest(resource_set_id=rsid,
                                                      scopes=scopes).to_dict())

        return prrs

    def do_permission_request(self, prrs):
        pat = self.rs_handler.token['PAT']

        kwargs = {
            "headers": {"Authorization": "Bearer %s" % pat},
            "body": prrs}

        url = self.client.provider_info["rpt_endpoint"]
        resp = self.client.send(url, "POST", **kwargs)

        assert resp.status == "201 Created"
        return PermissionRegistrationResponse().from_json(resp.message)[
            "ticket"]

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
            resp = self.client.do_register_permission_request(
                self.resource_owner, json.dumps(rssp))
        else:
            self.do_introspection(rpt)

        return Response
