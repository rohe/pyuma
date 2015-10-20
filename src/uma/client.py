import base64
import logging

from oic import oic
from oic.exception import MissingSession

from oic.oauth2 import rndstr
from oic.oauth2.message import AuthorizationRequest
from oic.oauth2 import dynreg
from oic.oic.message import ProviderConfigurationResponse
from oic.utils.authn.authn_context import PASSWORD
from uma.message import AuthorizationDataRequest, ResourceSetDescription, \
    ResourceSetResponse
from uma.message import IntrospectionRequest
from uma.message import PermissionRegistrationRequest
from uma.message import ProviderConfiguration
from uma.message import RPTResponse

from uma import AAT
from uma import PAT
from uma.message import RPTRequest

from oic.oic import AuthorizationResponse, PARAMMAP, OIDCONF_PATTERN
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect
# from oic.utils.http_util import R2C

from uma import UMAError
from uma.message import PermissionRegistrationResponse

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


class ConnectionFailure(Exception):
    pass


UMA_SCOPE = {"AAT": AAT, "PAT": PAT}

UMACONF_PATTERN = "%s/.well-known/uma-configuration"

DEF_SIGN_ALG = {"id_token": "RS256",
                "openid_request_object": "RS256",
                "client_secret_jwt": "HS256",
                "private_key_jwt": "HS256"}


class Client(dynreg.Client):
    """ An UMA client implementation based on OAuth2 with Dyn Reg.
    """
    # noinspection PyUnusedLocal
    def __init__(self, client_id=None, ca_certs=None, client_prefs=None,
                 client_authn_methods=None, keyjar=None, conf=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope="",
                 verify_ssl=True):

        config = {"authz_page": authz_page,
                  "response_type": response_type,
                  "scope": scope}

        dynreg.Client.__init__(self, client_id, ca_certs, client_authn_methods,
                               keyjar, verify_ssl)

        self.oidc_client = oic.Client(client_id, ca_certs, client_prefs,
                                      client_authn_methods, keyjar, verify_ssl)

        self.provider_info = None
        # token per user
        self.token = {}
        self.behaviour = {
            "require_signed_request_object":
                DEF_SIGN_ALG["openid_request_object"]}

        self.conf = conf or {}
        self.registration_info = registration_info
        self.flow_type = flow_type
        self.scope = scope
        self.state = {}
        self.allow = {}
        self.keyjar = None
        self.client_id = ""
        self.client_secret = ""
        self.request2endpoint.update({
            "RegistrationRequest": "dynamic_client_endpoint",
            "TokenRequest": "token_endpoint",
            "AuthorizationRequest": "authorization_endpoint",
            "RequestingPartyClaimsRequest": "requesting_party_claims_endpoint",
            "IntrospectionRequest": "introspection_endpoint",
            "ResourceSetDescription": "resource_set_registration_endpoint",
            "PermissionRegistrationRequest": "permission_registration_endpoint",
            # "AuthorizationDataRequest": "authorization_data_request_endpoint",
            "RPTRequest": "rpt_endpoint"
        })

    def init_relationship(self, provider_url):
        if not self.provider_info:
            opc = ProviderConfigurationResponse()
            try:
                pcr = self.provider_config(provider_url,
                                           serv_pattern=UMACONF_PATTERN)
            except Exception as err:
                raise
            else:
                opc.update(pcr)

            if 'oidc_provider' in self.conf:
                try:
                    pcr = self.oidc_client.provider_config(provider_url)
                except Exception as err:
                    raise
                else:
                    opc.update(pcr)

            self.provider_info = opc

        if not self.client_secret:
            self.register(
                self.provider_info["dynamic_client_endpoint"])

    @staticmethod
    def get_uma_scope(token_type):
        if token_type in ["AAT", "PAT"]:
            return UMA_SCOPE[token_type]

    def acquire_grant(self, resource_server, token_type, userid, state="",
                      acr=PASSWORD, authn_method="", **kwargs):
        """
        Get a grant by which a PAT/AAT token later can be acquired from the
        server

        :param resource_server: The OP to use
        :param token_type: Which kind of token to acquire
        :param userid: On behalf of which user
        :param state:
        :param acr: Authentication Context Reference
        :param authn_method:
        """

        self.init_relationship(resource_server)

        if token_type == "RPT" and not "AAT" in self.token:
            # Must have AAT first
            resp = self.acquire_grant(resource_server, "AAT", userid, state,
                                      acr, authn_method, **kwargs)
            return resp

        # And eventually do an Authorization request
        if not state:
            state = rndstr(16)
        self.state[state] = userid

        request_args = {"response_type": "code",
                        "client_id": self.client_id,
                        "redirect_uri": self.redirect_uris[0],
                        "scope": [self.get_uma_scope(token_type), "openid"],
                        "state": state,
                        "acr_values": [acr]}

        if authn_method:
            narg = {"authn_method": authn_method,
                    "user": userid}
            try:
                narg["password"] = kwargs["password"]
            except KeyError:
                pass
        else:
            narg = {}

        url, body, ht_args, csi = self.request_info(AuthorizationRequest,
                                                    "GET", request_args, **narg)

        if "headers" in ht_args:
            if "auth" in ht_args["headers"]:
                u, p = ht_args["headers"]["auth"]
                ht_args["headers"]["Authorization"] = base64.b64encode(
                    "Basic %s:%s" % (u, p))
                del ht_args["headers"]["auth"]

            ht_args = [(k, v) for k, v in list(ht_args["headers"].items())]
        else:
            ht_args = []

        url = url.encode("utf8")
        # construct the redirect
        return Redirect(url, headers=ht_args)

    def acquire_access_token(self, aresp, token_type, userid=""):
        """
        This is where I should continue when I have the response of a
        authorization request.

        :param aresp: The Authorization response
        :param token_type: The type of access token ("PAT", "PRT", "AAT")
        :param userid: The user (user+sp) I working for
        """

        if isinstance(self.state, dict):
            try:
                uid = self.state[aresp["state"]]
            except KeyError:
                raise MissingSession("Unknown state value")
        else:
            try:
                uid = ""
                assert self.state == aresp["state"]
            except AssertionError:
                raise MissingSession("Unknown state value")

        if not uid:
            uid = userid

        self.grant[aresp["state"]] = self.grant_class(resp=aresp)
        req_args = {"code": aresp["code"], "scope": aresp["scope"]}

        atresp = self.do_access_token_request(request_args=req_args,
                                              state=aresp["state"],
                                              keyjar=self.keyjar)

        # if not uid:
        #    uid = atresp["id_token"]["sub"]

        try:
            self.token[uid][token_type] = atresp
        except KeyError:
            self.token[uid] = {token_type: atresp}

        return uid

    def create_authorization_data_request(self, userid, ticket):
        adr = AuthorizationDataRequest(
            ticket=ticket, rpt=self.token[userid]["RPT"])
        _aat = self.token[userid]["AAT"]["access_token"]
        kwargs = {"headers": {"Authorization": "Bearer %s" % _aat},
                  "data": adr.to_json()}
        return kwargs

    def authorization_data_request(self, userid, ticket):
        kwargs = self.create_authorization_data_request(userid, ticket)
        url = self.provider_info["authorization_request_endpoint"]
        return self.send(url, "POST", **kwargs)

    def create_rpt_request(self, user):
        _aat = self.token[user]["AAT"]["access_token"]
        kwargs = {"headers": {"Authorization": "Bearer %s" % _aat}}
        return kwargs

    def get_rpt(self, user):
        kwargs = self.create_rpt_request(user)
        url = self.provider_info["rpt_endpoint"]
        resp = self.send(url, "POST", **kwargs)

        if resp.status_code == 200:
            rptr = RPTResponse().from_json(resp.text)
            self.token[user]["RPT"] = rptr["rpt"]
        else:
            raise UMAError(resp.reason)

    def construct_RPTRequest(self, request=RPTRequest, request_args=None,
                             extra_args=None, **kwargs):

        return self.construct_request(request, request_args, extra_args)

    def construct_IntrospectionRequest(self, request=IntrospectionRequest,
                                       request_args=None, extra_args=None,
                                       **kwargs):
        return self.construct_request(request, request_args, extra_args)

    def construct_PermissionRegistrationRequest(
            self, request=PermissionRegistrationRequest, request_args=None,
            extra_args=None, **kwargs):
        return self.construct_request(request, request_args, extra_args)

    def construct_AuthorizationDataRequest(
            self, request=AuthorizationDataRequest, request_args=None,
            extra_args=None, **kwargs):
        return self.construct_request(request, request_args, extra_args)

    def construct_ResourceSetDescription(self, request=ResourceSetDescription,
                                         request_args=None, extra_args=None,
                                         **kwargs):
        return self.construct_request(request, request_args, extra_args)

    def uma_match_preferences(self, pcr=None, issuer=None):
        pass

    def match_preferences(self, pcr=None, issuer=None):
        if isinstance(pcr, ProviderConfigurationResponse):
            return self.oidc_client.match_preferences(pcr, issuer)
        else:
            return self.uma_match_preferences(pcr, issuer)

    def dynamic(self, authsrv):
        """ Do dynamic provider information gathering and client registration

        :param authsrv: Authorization Server URL
        """
        # Dynamically read server info
        provider_conf = self.provider_config(authsrv,
                                             response_cls=ProviderConfiguration,
                                             serv_pattern=UMACONF_PATTERN)
        dce = provider_conf["dynamic_client_endpoint"]
        logger.debug("Got provider config: %s" % provider_conf)

        logger.debug("Registering RP")
        reg_info = self.register(dce, **self.registration_info)
        logger.debug("Registration response: %s" % reg_info)


# the API to the UMA protected IDP system that the IdP uses


class UMAClient():
    def __init__(self, client_name, redirect_uris, acr="",
                 verify_ssl=True):

        # The UMA Client
        reginfo = {
            "client_name": client_name,
            "application_type": "native",
            "redirect_uris": redirect_uris
        }

        self.client = Client(
            {}, client_authn_methods=CLIENT_AUTHN_METHOD,
            registration_info=reginfo, verify_ssl=verify_ssl)

        self.client.redirect_uris = redirect_uris
        self.acr = acr
        self.registration_response = None

    def __call__(self, resource, requestor, oper="GET", **kwargs):
        """
        This is the main API

        :param resource: resource definition
        :param requestor: The entity_id of the SP that requests the information
        :param attrs: which attributes to return
        :param state: Where in the process am I
        :param typ: Type of operation ['GET', 'POST', 'PUT', ..]
        """
        return self.operation(resource, requestor, oper, **kwargs)

    def rs_query(self, resource, requestor, oper="GET", **kwargs):
        """

        :param resource: resource definition
        :param requestor: an identifier representing the requestor
        :param oper: HTTP operation ['GET', 'POST, ...]
        """
        try:
            rpt = self.client.token[requestor]["RPT"]
        except KeyError:
            rpt = None

        if rpt:
            _args = {"headers": {"Authorization": "Bearer %s" % rpt}}
        else:
            _args = {}

        return self.client.send(resource, oper, **_args)

    def operation(self, resource, requestor, oper="GET", **kwargs):
        """

        :param owner: user identifier
        :param requestor: The entity_id of the SP that requests the information
        :param attrs: which attributes to return
        :param state: Where in the process am I
        """
        try:
            state = kwargs["state"]
        except KeyError:
            state = rndstr()
            self.client.state[requestor] = state

        try:
            authn_method = kwargs["authn_method"]
        except:
            authn_method = ""

        resp = self.rs_query(resource, requestor, oper, **kwargs)

        if resp.status_code == 200:
            return Response(resp.text)

        if resp.status_code == 401:  # No RPT
            as_uri = resp.headers["as_uri"]
            resp = self.client.acquire_grant(as_uri, "RPT", requestor, state,
                                             self.acr, authn_method)
            return resp
            # elif resp.status_code == 302:  # which it should be
            #     # redirect that are part of the grant code flow
            #     headers = [(a, b) for a, b in resp.headers.items()
            #                if a != "location"]
            #     return Redirect(resp.headers["location"], headers=headers)
            # elif resp.status_code == 200:  # ???
            #     return Response(resp.text)
            # else:
            #     return R2C[resp.status_code](resp.text)

        if resp.status_code == 403:  # Permission registered, got ticket
            if state == "403":  # loop ?
                return {}
            prr = PermissionRegistrationResponse().from_json(resp.text)
            resp = self.client.authorization_data_request(requestor,
                                                          prr["ticket"])
            if resp.status_code in (200, 201):
                return self.operation(resource, requestor, oper, **kwargs)

        raise UMAError()

    def get_tokens(self, query):
        aresp = AuthorizationResponse().from_urlencoded(query)
        uid = self.client.acquire_access_token(aresp, "AAT")
        self.client.get_rpt(uid)
        return uid

    def sign_enc_algs(self, typ):
        resp = {}
        for key, val in list(PARAMMAP.items()):
            try:
                resp[key] = self.registration_response[val % typ]
            except (TypeError, KeyError):
                if key == "sign":
                    resp[key] = DEF_SIGN_ALG["id_token"]
        return resp
