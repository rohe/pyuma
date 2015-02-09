import json
import logging
import sys
import traceback
import time

from oic.oauth2 import AuthorizationRequest
from oic.oauth2 import AuthorizationResponse
from oic.oauth2 import PBase
from oic.utils.http_util import Response, Redirect, ServiceError
from oic.utils.http_util import R2C
from oic.utils.webfinger import WebFinger

from uma import UMAError
from uma.authzsrv import OAuth2UmaAS
from uma.client import Client, UMACONF_PATTERN
from uma.message import RPTResponse, ProviderConfiguration
from uma.message import PermissionRegistrationResponse
from uma.resourcesrv import ResourceServer1C

logger = logging.getLogger(__name__)

__author__ = 'roland'


def trace(func, from_to, **kwargs):
    info = {
        "time": time.time(),
        "func": func,
        "from_to": from_to
    }
    if "response" in kwargs:
        _resp = kwargs["response"]
        try:
            info.update({"response": _resp.message,
                         "status_code": _resp.status,
                         "headers": _resp.headers})
        except AttributeError:
            info.update({"response": _resp.text,
                         "status_code": _resp.status_code,
                         "headers": _resp.headers})
        del kwargs["response"]
    if kwargs:
        info.update(kwargs)

    return json.dumps(info)


class UmaCAS(object):
    def __init__(self, name, sdb, cdb, authn_broker, authz,
                 client_authn, symkey, urlmap=None, as_keyjar=None,
                 as_configuration=None, base_url="",
                 client_authn_methods=None, authn_at_registration="",
                 client_info_url="", secret_lifetime=86400,
                 # client conf below
                 client_id=None, ca_certs=None,
                 client_authn_method=None, c_keyjar=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope="",
                 acr="", resource_srv=""):

        self.authzsrv = OAuth2UmaAS(name, sdb, cdb, authn_broker, authz,
                                    client_authn, symkey, urlmap,
                                    as_keyjar, configuration=as_configuration,
                                    base_url=base_url,
                                    client_authn_methods=client_authn_methods,
                                    authn_at_registration=authn_at_registration,
                                    client_info_url=client_info_url,
                                    secret_lifetime=secret_lifetime)
        self.client = Client(client_id, ca_certs, client_authn_method,
                             c_keyjar, server_info, authz_page, flow_type,
                             password, registration_info, response_type,
                             scope)

        self.client.redirect_uris = self.client.registration_info[
            "redirect_uris"]
        self.baseurl = self.authzsrv.baseurl
        self.resource_srv = resource_srv
        self.acr = acr
        self.trace = []

    def get_aat(self, user):
        request_args = {"response_type": "code",
                        "client_id": "internal",
                        "redirect_uri": self.client.redirect_uris[0],
                        "scope": [self.client.get_uma_scope("AAT")],
                        "state": "_state"}

        areq = AuthorizationRequest(**request_args)
        self.trace.append(trace("get_aat", "C-->AS", query=areq.to_dict(),
                                user=user))
        sid = self.authzsrv.sdb.create_authz_session(user, areq)
        grant = self.authzsrv.sdb[sid]["code"]
        self.client.token[user] = {
            "AAT": self.authzsrv.sdb.upgrade_to_token(grant)}
        self.trace.append(trace(
            "get_aat", "C<--AS",
            data={"AAT": self.client.token[user]["AAT"]["access_token"]}))

    # C <-> AS internal communication
    def rpt_endpoint(self, authn, **kwargs):
        return self.authzsrv.rpt_endpoint(authn)

    def get_rpt(self, user):
        authn = "Bearer %s" % self.client.token[user]["AAT"]["access_token"]
        self.trace.append(trace("*get_rpt", "C-->AS", authn_info=authn))
        resp = self.rpt_endpoint(authn)
        rtr = RPTResponse().from_json(resp.message)
        self.client.token[user]["RPT"] = rtr["rpt"]
        self.trace.append(trace("*get_rpt", "C<--AS",
                                data={"RPT":self.client.token[user]["RPT"]}))

    def authorization_request_endpoint(self, data, authn):
        self.trace.append(trace("*authorization_request", "C-->AS",
                                authn_info=authn, query=data))
        return self.authzsrv.authorization_request_endpoint(data, authn)

    def resource_sets_by_user(self, uid):
        return self.authzsrv.resource_sets_by_user(uid)

    def store_permission(self, user, requestor, resource_id, scopes):
        return self.authzsrv.store_permission(user, requestor, resource_id,
                                              scopes)

    # client stuff

    def rs_query(self, requestor, path):
        try:
            rpt = self.client.token[requestor]["RPT"]
        except KeyError:
            rpt = None

        url = "%s/%s" % (self.resource_srv, path)

        if rpt:
            kwargs = {"headers": [("Authorization", "Bearer %s" % rpt)]}
            self.trace.append(trace("rs_query", "C-->RS",
                                    authn_info="Bearer %s" % rpt, url=url))
        else:
            kwargs = {}
            self.trace.append(trace("rs_query", "C-->RS", url=url))

        return self.client.send(url, "GET", **kwargs)

    def get_info(self, requester, path, state=""):
        """

        :param requester: requester
        """
        resp = self.rs_query(requester, path)
        self.trace.append(trace("rs_query", "C<--RS", response=resp))

        if resp.status_code == 200:
            return Response(resp.text)

        if resp.status_code == 401:  # No RPT
            as_uri = resp.headers["as_uri"]
            if as_uri == self.baseurl:
                # It's me as it should be, means get a RPT from myself
                self.get_aat(requester)
                self.get_rpt(requester)

                return self.get_info(requester, path, state)

            else:
                return R2C[500]("Wrong AS")

        if resp.status_code == 403:  # Permission registered, got ticket
            prr = PermissionRegistrationResponse().from_json(resp.text)
            kwargs = self.client.create_authorization_data_request(
                requester, prr["ticket"])
            resp = self.authorization_request_endpoint(
                kwargs["data"], kwargs["headers"]["Authorization"])
            self.trace.append(trace("*authorization_request", "C<--AS",
                                    response=resp))
            if resp.status == "200 OK":
                return self.get_info(requester, path)

        raise UMAError()

    def get_tokens(self, query):
        aresp = AuthorizationResponse().from_urlencoded(query)
        uid = self.client.acquire_access_token(aresp, "AAT")
        self.client.get_rpt(uid)
        return uid


class UmaCRS(object):
    def __init__(self, dataset, symkey="", rs_keyjar=None, baseurl="",
                 # client conf below
                 client_id=None, ca_certs=None,
                 client_authn_method=None, c_keyjar=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope="",
                 ca_bundle=None):

        self.ressrv = ResourceServer1C.__init__(
            dataset, symkey, client_id, ca_certs, client_authn_method,
            rs_keyjar, server_info, authz_page, flow_type, password,
            registration_info, response_type, scope, baseurl)

        self.client = Client(client_id, ca_certs, client_authn_method,
                             c_keyjar, server_info, authz_page, flow_type,
                             password, registration_info, response_type,
                             scope)

        self.ca_bundle = ca_bundle

    def find_srv_discovery_url(self, resource):
        """
        Use Webfinger to find the OP, The input is a unique identifier
        of the user. Allowed forms are the acct, mail, http and https
        urls. If no protocol specification is given like if only an
        email like identifier is given. It will be translated if possible to
        one of the allowed formats.

        :param resource: unique identifier of the user.
        :return:
        """

        if self.ca_bundle:
            args = {"ca_certs": self.ca_bundle}
        else:
            args = {}
        wf = WebFinger(httpd=PBase(**args))
        self.ressrv.srv_discovery_url = wf.discovery_query(resource)

    def _as_provider_config(self, authzsrv, role):
        # Dynamically read server info
        provider_conf = role.provider_config(
            authzsrv, response_cls=ProviderConfiguration,
            serv_pattern=UMACONF_PATTERN)
        return provider_conf

    def _as_register(self, endpoint, role):
        reg_info = role.register(endpoint, **self.ressrv.registration_info)
        return reg_info

    def rs_as_provider_config(self, authzsrv):
        return self._as_provider_config(authzsrv, self.ressrv)

    def cli_as_provider_config(self, authzsrv):
        return self._as_provider_config(authzsrv, self.client)

    def rs_as_register(self, endpoint):
        return self._as_register(endpoint, self.ressrv)

    def cli_as_register(self, endpoint):
        return self._as_register(endpoint, self.client)

    def _create_authzreq(self, role, session, acr_value=""):
        request_args = role.get_request_args(acr_value, session)

        try:
            url, body, ht_args, csi = role.request_info(
                AuthorizationRequest, "GET", request_args=request_args)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            resp = ServiceError(message)
        else:
            resp_headers = [("Location", str(url))]

            if ht_args:
                resp_headers.extend([(a, b) for a, b in ht_args.items()])

            resp = Redirect(url, headers=resp_headers)
        return resp

    def rs_create_authzreq(self, session, acr_value=""):
        return self._create_authzreq(self.ressrv, session, acr_value)

    def cli_create_authzreq(self, session, acr_value=""):
        return self._create_authzreq(self.client, session, acr_value)

    def _do_access_token_request(self, role):
        return role.do_access_token_request()

    def rs_do_access_token_request(self):
        return self._do_access_token_request(self.ressrv)

    def cli_do_access_token_request(self):
        return self._do_access_token_request(self.client)

    def register_resource_set_description(self, owner, resource_set_descr,
                                          path):
        self.ressrv.register_resource_set_description(owner,
                                                      resource_set_descr, path)


class UmaASRS(object):
    def __init__(self, dataset, symkey="", rs_keyjar=None, baseurl="",
                 # client conf below
                 client_id=None, ca_certs=None,
                 client_authn_method=None, c_keyjar=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope="",
                 ca_bundle=None):

        self.ressrv = ResourceServer1C.__init__(
            dataset, symkey, client_id, ca_certs, client_authn_method,
            rs_keyjar, server_info, authz_page, flow_type, password,
            registration_info, response_type, scope, baseurl)

        self.authzsrv = OAuth2UmaAS(name, sdb, cdb, authn_broker, authz,
                                    client_authn, symkey, urlmap,
                                    as_keyjar, configuration=as_configuration,
                                    base_url=base_url,
                                    client_authn_methods=client_authn_methods,
                                    authn_at_registration=authn_at_registration,
                                    client_info_url=client_info_url,
                                    secret_lifetime=secret_lifetime)

