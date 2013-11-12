import logging
from urllib import urlencode
from oic.oauth2 import Client
from oic.oauth2 import rndstr
from oic.oauth2 import JSON_ENCODED
from oic.oauth2.provider import Endpoint
from uma.message import IntrospectionRequest
from uma.message import IntrospectionResponse
from uma.message import PermissionRegistrationRequest
from uma.message import PermissionRegistrationResponse
from uma.message import ResourceSetDescription
from uma.message import StatusResponse
from uma.oidc import OpenIDConnect
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

DESC_BASE = "http://its.umu.se/uma/attr"


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


class ResourceServer(OpenIDConnect):
    def __init__(self, dataset, config=None, config_file="",
                 baseuri="", symkey="", **kwargs):
        OpenIDConnect.__init__(self, config, config_file, **kwargs)
        self.dataset = dataset
        self.symkey = symkey
        self.permreg = PermissionRegistry()
        self.request2endpoint = REQUEST2ENDPOINT

        self.endpoints = [DataSetEndpoint]
        self.server_environ = {}
        self.path2rsid = {}
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
        self.permreg.set(owner, "pat", pat)
        self.permreg.set(owner, "authzsrv", authzsrv)
        self.permreg.set(owner, "client_key", client_key)

    def dataset_endpoint(self, request, owner, environ, **kwargs):
        """
        The endpoint at which the Resource server presents its information

        :param request: Which resource that is wanted
        :param owner: The resource owner
        :param environ: WSGI environment dictionary
        :param kwargs: Extra keyword arguments
        """

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
            resp = self.do_introspection(owner, rpt, owner)

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
                    _path = parse_query(environ["PATH_INFO"])
                    rsid = self.path2rsid[_path]
                    resp = self.register_permission(owner, rsid,
                                                    permissons=[DESC_BASE])

                    return ErrorResponse(as_uri=_as,
                                         error="Forbidden",
                                         host_id="rs.example.com",
                                         ticket=resp["ticket"]).to_json()

        res = self.dataset(owner, resp["permissions"])
        return ResourceResponse(resource=res).to_json()

    def request_info(self, owner, msgtype, method=DEFAULT_METHOD,
                     authn_method="bearer_header", request_args=None,
                     extra_args=None):

        client = self.client[self.permreg.get(owner, "authzsrv")]
        return client, client.request_info(msgtype, method,
                                           request_args=request_args,
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
        client = self.client[self.permreg.get(owner, "authzsrv")]
        ir = IntrospectionRequest(token=rpt)

        if path:
            ir["resource_id"] = self.path2rsid[path]

        request_args = {"access_token": pat}
        ht_args = client.client_authn_method[
            "bearer_header"](self).construct(ir, request_args=request_args)

        url = client.provider_info.values()[0]["introspection_endpoint"]

        return client.request_and_return(url, IntrospectionResponse,
                                         body=ir.to_json(), body_type="json",
                                         http_args=ht_args)

    def _register(self, owner, method, endp, objekt=None, message=None,
                  rsid="", resp_cls=None):
        try:
            pat = self.permreg.get(owner, "pat")["access_token"]
            client = self.oic_client[self.permreg.get(owner, "client_key")]
            azs = self.permreg.get(owner, "authzsrv")
        except Exception, err:
            raise Unknown(owner)

        request_args = {"access_token": pat}
        if message:
            arg = message
        else:
            arg = {}
        ht_args = client.client_authn_method[
            "bearer_header"](self).construct(arg, request_args=request_args)

        url = client.provider_info[azs][endp]

        if rsid:
            if url.endswith("/"):
                url += rsid
            else:
                url += "/%s" % rsid

        if message:
            objekt = message.to_json()

        return client.request_and_return(url, resp_cls, method, objekt, "json",
                                         http_args=ht_args)

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
                              resp_cls=PermissionRegistrationResponse )

    def register_resource_set_description(self, owner, resource_set_descr,
                                          path, hashval):
        """
        Registers a resource set description at the Authorization server

        :param owner:
        :param resource_set_descr: Resource Set Description in a JSON
            format
        :param path: HTTP path at which the resource should be accessible
        :param hashval: A hash value constructed over the user info
        :returns: A StatusResponse instance
        """

        self.userinfo_hash[owner] = hash
        rsid = rndstr()
        response = self._register(owner, "PUT",
                                  endp="resource_set_endpoint",
                                  objekt=resource_set_descr,
                                  rsid=rsid,
                                  resp_cls=StatusResponse)

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

        pat = self.permreg.get(owner, "pat")["access_token"]
        client = self.client[self.permreg.get(owner, "authsrv")]

        url = client._endpoint(
            self.request2endpoint[ResourceSetDescription.__name__])

        if url.endswith("/"):
            url += rsid
        else:
            url = "%s/%s" % (url, rsid)

        ht_args = client.init_authentication_method(access_token=pat)

        return client.request_and_return(url, StatusResponse, "GET",
                                         http_args=ht_args)
