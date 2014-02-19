import logging
import traceback
from urllib import urlencode
from oic.oauth2 import rndstr, AuthorizationRequest
from oic.oauth2 import JSON_ENCODED
from oic.oauth2.provider import Endpoint
import sys
from oic.utils import http_util
from oic.utils.http_util import Response
from uma.client import Client
from uma.message import IntrospectionRequest
from uma.message import IntrospectionResponse
from uma.message import PermissionRegistrationRequest
from uma.message import PermissionRegistrationResponse
from uma.message import ResourceSetDescription
from uma.message import StatusResponse
from uma.saml2uma import ErrorResponse
from uma.saml2uma import ResourceResponse

logger = logging.getLogger(__name__)

__author__ = 'rolandh'


class Unknown(Exception):
    pass


class UnknownAuthzSrv(Exception):
    pass


def client_init(ca_certs, client_authn_method, config):
    _client = Client(ca_certs=ca_certs, client_authn_method=client_authn_method)
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


class ResourceServerBase(object):
    def __init__(self, dataset, symkey="", baseurl=""):
        self.dataset = dataset
        self.symkey = symkey
        self.permreg = PermissionRegistry()
        self.request2endpoint = REQUEST2ENDPOINT
        self.baseurl = baseurl

        self.endpoints = [DataSetEndpoint]
        self.server_environ = {}

        # The relationship between a URL path and which resource id the
        # resource is stored under
        self.path2rsid = {}

        # A hash per resource (=user info) to allow simple check if
        # something has changed.
        self.userinfo_hash = {}

    @staticmethod
    def _get_bearer_token(environ):
        try:
            _authz = environ["HTTP_AUTHORIZATION"]
            if _authz.startswith("Bearer"):
                return _authz[len("Bearer "):]
            else:
                return None
        except KeyError:
            return None

    def authz_registration(self, owner, pat, authzsrv, client_key):
        """
        Note this only works if there is *one* resource per owner!!!

        :param owner: The user id of the resource owner
        :param pat: A TokenResponse instance
        :param authzsrv: A URL pointing to the provider info of the authz server
        :param client_key: A unique identifier of the client
        """

        self.permreg.set(owner, "pat", pat)
        self.permreg.set(owner, "authzsrv", authzsrv)
        self.permreg.set(owner, "client_key", client_key)

    def dataset_access(self, owner, environ, resource):
        # It there a RPT
        rpt = self._get_bearer_token(environ)
        if not rpt:  # No RPT
            # return information about the AS
            try:
                _as = self.permreg.get(owner, "authzsrv")
            except Unknown:
                raise UnknownAuthzSrv(owner)

            return ErrorResponse(as_uri=_as, error="Missing RPT",
                                 host_id="rs.example.com").to_json()
        else:
            _as = self.permreg.get(owner, "authzsrv")
            _pat = self.permreg.get(owner, "pat")["access_token"]
            # verify the RPT
            resp = self.do_introspection(owner, rpt, resource)

            if not resp["active"]:
                return ErrorResponse(as_uri=_as,
                                     error="Unauthorized",
                                     host_id="rs.example.com").to_json()
            else:
                # verify that the permissions are sufficient, which in this
                # case is the same as there is some
                try:
                    assert resp["permissions"]
                except (AssertionError, KeyError):
                    fpath = self.dataset.filename(resource)
                    rsid = self.path2rsid[fpath]

                    # try:
                    #     query = parse_qs(environ["QUERY_STRING"])
                    #     _perms = ["%s/%s" % (DESC_BASE, v) for v in
                    #               query["attr"]]
                    # except KeyError:
                    #     _perms = [DESC_BASE]

                    _perms = [self.dataset.get_necessary_scope(environ)]

                    resp = self.register_permission(owner, rsid,
                                                    permissons=_perms)
                    return ErrorResponse(as_uri=_as,
                                         error="Forbidden",
                                         host_id="rs.example.com",
                                         ticket=resp["ticket"]).to_json()
                else:
                    return resp

    def dataset_endpoint(self, request, owner, environ, **kwargs):
        """
        The endpoint at which the Resource server presents its information

        :param request: Which resource that is wanted
        :param owner: The resource owner
        :param environ: WSGI environment dictionary
        :param kwargs: Extra keyword arguments
        """

        resp = self.dataset_access(owner, environ, request)
        if isinstance(resp, ErrorResponse):
            return resp

        res = self.dataset(owner, resp["permissions"])
        return ResourceResponse(resource=res).to_json()

    def rs_request_info(self, owner, msgtype, method=DEFAULT_METHOD,
                        authn_method="bearer_header", request_args=None,
                        extra_args=None):

        pass

    def do_introspection(self, owner, rpt, resource=None):
        """
        The resource server doing introspection on a RPT at the AuthzServer

        :param owner: The owner of the resource
        :param rpt: Resource access token
        :param resource: the resource
        :returns:
        """

        return {}

    def register_init(self, owner, endp, message=None, rsid=""):
        """
        :param owner: The resource owner
        :param endp: The endpoint the message should be sent to
        :param message: The registration message as a class instance
        :param rsid: Resource set identifier
        :return: Tuple of client instance, url to send the message to and
            HTTP request arguments
        """
        return None, "", ""

    def _register(self, owner, method, endp, objekt=None, message=None,
                  rsid="", resp_cls=None):
        """

        :param owner: The owner of the resource
        :param method: Which HTTP method to use
        :param endp: The HTTP endpoint
        :param objekt: An object, it's either this or the message that is
            sent
        :param message: Only one of objekt or message can be present
        :param rsid: Resource ID
        :param resp_cls: Which class the response should be of
        :return: A *RegistrationResponse instance
        """
        return {}

    def register_permission(self, owner, resource_set_id, permissons):
        """
        The resource server registering resource set descriptions at the
        Authz server

        :param owner: The owner of the resource
        :param resource_set_id: An identifier of the resource set
        :param permissons: A set of urls representing possible actions on the
            resource.
        :returns: A PermissionRegistrationResponse instance
        """

        prr = PermissionRegistrationRequest(resource_set_id=resource_set_id,
                                            scopes=permissons)

        return self._register(owner, DEFAULT_METHOD,
                              endp="permission_registration_endpoint",
                              message=prr,
                              resp_cls=PermissionRegistrationResponse)

    def register_resource_set_description(self, owner, resource_set_descr,
                                          path):
        """
        Registers a resource set description at the Authorization server

        :param owner:
        :param resource_set_descr: Resource Set Description in a JSON
            format
        :param path: HTTP path at which the resource should be accessible
        :returns: A StatusResponse instance
        """

        rsid = rndstr()
        response = self._register(
            owner, "PUT", endp="resource_set_registration_endpoint",
            objekt=resource_set_descr, rsid=rsid, resp_cls=StatusResponse)

        # StatusResponse
        assert response["status"] == "created"

        self.path2rsid[path] = rsid
        csi = dict(resource_set_descr=resource_set_descr)
        csi["_id"] = response["_id"]
        csi["_rev"] = response["_rev"]
        csi["rsid"] = rsid
        self.permreg.add_resource_set_description(owner, csi)

    # def update_resource_set_description(self, owner, rsid, **kwargs):
    #     """
    #     Updates a resource set description at the Authorization server
    #
    #     :param owner:
    #     :param rsid: The resource set identifier
    #     :param kwargs: Whatever should be changed
    #     :returns: A StatusResponse instance
    #     """
    #     authzsrv = self.permreg.get(owner, "authsrv")
    #     pat = self.permreg.get(owner, "pat")
    #
    #     client = self.client[authzsrv]
    #     csi = ResourceSetDescription(
    #         **self.permreg.get(owner, "resource_set").to_dict())
    #
    #     for param in csi.parameters():
    #         if param in ["_id", "_rev"]:  # Don't mess with these
    #             continue
    #         else:
    #             try:
    #                 csi[param] = kwargs[param]
    #             except KeyError:
    #                 pass
    #
    #
    #     method = "PUT"
    #     url, body, ht_args, csi = client.request_info(
    #         ResourceSetDescription, method=method,
    #         request_args=req_args, extra_args={"access_token": pat},
    #         authn_method="bearer_header")
    #
    #     return client.request_and_return(url, StatusResponse,
    #                                      method, body, body_type="json",
    #                                      http_args=ht_args)

    def read_resource_set_description(self, owner, rsid):
        """
        Reads a resource set description from the Authorization server

        :param rsid:
        :returns: A ResourceSetDescription instance
        """
        return {}

    def is_resource_set_changed(self, rsid, val):
        return val == self.userinfo_hash[rsid]


class ResourceServer1C(ResourceServerBase, Client):
    def __init__(self, dataset, symkey="", client_id=None,
                 ca_certs=None, client_authn_method=None, keyjar=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope="",
                 **kwargs):
        ResourceServerBase.__init__(self, dataset, symkey)
        Client.__init__(self, client_id, ca_certs, client_authn_method, keyjar,
                        server_info, authz_page, flow_type, password,
                        registration_info, response_type, scope)
        self.kwargs = kwargs
        self.srv_discovery_url = ""
        self.cookie_handler = http_util.CookieDealer(self)
        self.cookie_name = "resourceserver1c"

    def rs_request_info(self, owner, msgtype, method=DEFAULT_METHOD,
                        authn_method="bearer_header", request_args=None,
                        extra_args=None):

        return self.request_info(msgtype, method, request_args=request_args,
                                 extra_args=extra_args,
                                 authn_method=authn_method,
                                 content_type=JSON_ENCODED)

    def do_introspection(self, owner, rpt, path=None):
        """
        The resource server doing introspection on a RPT at the AuthzServer

        :param owner: The owner of the resource
        :param rpt: Resource access token
        :param path: path representing the resource
        :returns:
        """

        pat = self.permreg.get(owner, "pat")["access_token"]
        ir = IntrospectionRequest(token=rpt)

        if path:
            fpath = self.dataset.filename(path)
            ir["resource_id"] = self.path2rsid[fpath]

        request_args = {"access_token": pat}
        ht_args = self.client_authn_method[
            "bearer_header"](self).construct(ir, request_args=request_args)

        url = self.provider_info.values()[0]["introspection_endpoint"]

        return self.request_and_return(url, IntrospectionResponse,
                                       body=ir.to_json(), body_type="json",
                                       http_args=ht_args)

    def register_init(self, owner, endp, message=None, rsid=""):
        """
        :param owner: The resource owner
        :param endp: The endpoint the message should be sent to
        :param message: The registration message as a class instance
        :param rsid: Resource set identifier
        :return: Tuple of client instance, url to send the message to and
            HTTP request arguments
        """
        try:
            pat = self.permreg.get(owner, "pat")["access_token"]
        except Exception, err:
            raise Unknown(owner)
        else:
            azs = self.permreg.get(owner, "authzsrv")

        request_args = {"access_token": pat}

        if message:
            arg = message
        else:
            arg = {}

        ht_args = self.client_authn_method[
            "bearer_header"](self).construct(arg, request_args=request_args)

        url = self.provider_info[azs][endp]

        if rsid:
            if url.endswith("/"):
                url += "resource_set/%s" % rsid
            else:
                url += "/resource_set/%s" % rsid

        return url, ht_args

    def _register(self, owner, method, endp, objekt=None, message=None,
                  rsid="", resp_cls=None):

        url, ht_args = self.register_init(owner, endp, message, rsid)

        if message:
            objekt = message.to_json()

        return self.request_and_return(url, resp_cls, method, objekt, "json",
                                       http_args=ht_args)

    # def update_resource_set_description(self, owner, rsid, **kwargs):
    #     """
    #     Updates a resource set description at the Authorization server
    #
    #     :param owner:
    #     :param rsid: The resource set identifier
    #     :param kwargs: Whatever should be changed
    #     :returns: A StatusResponse instance
    #     """
    #     authzsrv = self.permreg.get(owner, "authsrv")
    #     pat = self.permreg.get(owner, "pat")
    #
    #     client = self.client[authzsrv]
    #     csi = ResourceSetDescription(
    #         **self.permreg.get(owner, "resource_set").to_dict())
    #
    #     for param in csi.parameters():
    #         if param in ["_id", "_rev"]:  # Don't mess with these
    #             continue
    #         else:
    #             try:
    #                 csi[param] = kwargs[param]
    #             except KeyError:
    #                 pass
    #
    #
    #     method = "PUT"
    #     url, body, ht_args, csi = client.request_info(
    #         ResourceSetDescription, method=method,
    #         request_args=req_args, extra_args={"access_token": pat},
    #         authn_method="bearer_header")
    #
    #     return client.request_and_return(url, StatusResponse,
    #                                      method, body, body_type="json",
    #                                      http_args=ht_args)

    def read_resource_set_description(self, owner, rsid):
        """
        Reads a resource set description from the Authorization server

        :param rsid:
        :returns: A ResourceSetDescription instance
        """

        pat = self.permreg.get(owner, "pat")["access_token"]

        url = self._endpoint(
            self.request2endpoint[ResourceSetDescription.__name__])

        if url.endswith("/"):
            url += rsid
        else:
            url = "%s/%s" % (url, rsid)

        ht_args = self.init_authentication_method(
            {}, access_token=pat, authn_method=self.client_authn_method)

        return self.request_and_return(url, StatusResponse, "GET",
                                       http_args=ht_args)

    def begin(self, environ, start_response, session, acr_value=""):
        """Step 1: Get a access grant.

        :param environ:
        :param start_response:
        :param session:
        """
        client = self

        if not self.client_id and self.srv_discovery_url:
            self.dynamic(self.srv_discovery_url)

        request_args = self.get_request_args(acr_value, session)

        try:
            url, body, ht_args, csi = self.request_info(
                AuthorizationRequest, "GET", request_args=request_args)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(environ, start_response, (
                False, "Authorization request can not be performed!"))

        logger.debug("URL: %s" % url)
        logger.debug("ht_args: %s" % ht_args)

        session["client"] = client
        resp_headers = [("Location", str(url))]

        if ht_args:
            resp_headers.extend([(a, b) for a, b in ht_args.items()])
        logger.debug("resp_headers: %s" % resp_headers)
        start_response("302 Found", resp_headers)
        return []

    def get_request_args(self, acr_value, session):
        """
        :param acr_value: Authentication Context reference
        :param session: Session information
        :return: A set of Authorization request arguments
        """
        self.state = rndstr()
        request_args = {
            "response_type": self.flow_type,
            "scope": self.scope,
            "state": self.state,
        }
        if acr_value:
            request_args["acr_values"] = [acr_value]

        if self.flow_type == "token":
            request_args["nonce"] = rndstr(16)
            session["nonce"] = request_args["nonce"]
        else:
            use_nonce = getattr(self, "use_nonce", None)
            if use_nonce:
                request_args["nonce"] = rndstr(16)
                session["nonce"] = request_args["nonce"]

        logger.debug("request_args: %s" % (request_args,))

        return request_args

    def result(self, environ, start_response, result):
        resp = Response(mako_template="opresult.mako",
                        template_lookup=self.kwargs["template_lookup"],
                        headers=[])
        argv = {
            "result": result
        }
        return resp(environ, start_response, **argv)
