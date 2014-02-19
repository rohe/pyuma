import logging
import urllib
from oic.oauth2 import rndstr
from oic.oauth2.exception import MissingSession
from oic.oauth2 import dynreg
from oic.oic.message import ProviderConfigurationResponse
from oic.utils.authn.authn_context import PASSWORD
from uma.message import AuthorizationDataRequest
from uma.message import IntrospectionRequest
from uma.message import PermissionRegistrationRequest
from uma.message import ProviderConfiguration
from uma.message import RPTResponse
from uma import UMAError
from uma import AAT
from uma import PAT
from uma.message import RPTRequest

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
    #noinspection PyUnusedLocal
    def __init__(self, client_id=None, ca_certs=None,
                 client_authn_method=None, keyjar=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope=""):

        config = {"authz_page": authz_page,
                  "response_type": response_type,
                  "scope": scope}

        dynreg.Client.__init__(self, client_id, ca_certs, client_authn_method,
                               keyjar)

        self.provider_info = {}
        # token per user
        self.token = {}
        self.behaviour = {
            "require_signed_request_object":
            DEF_SIGN_ALG["openid_request_object"]}

        self.registration_info = registration_info
        self.flow_type = flow_type
        self.scope = scope
        self.state = []
        self.allow = {}
        self.state = ""
        self.keyjar = None
        self.client_id = ""
        self.client_secret = ""
        self.request2endpoint.update({
            "RegistrationRequest": "dynamic_client_endpoint",
            "AuthorizationRequest": "user_endpoint",
            "ResourceSetDescription": "resource_set_registration_endpoint",
            "IntrospectionRequest": "introspection_endpoint",
            "PermissionRegistrationRequest": "permission_registration_endpoint",
            "AuthorizationDataRequest": "authorization_data_request_endpoint",
            "RPTRequest": "rpt_endpoint"
        })

    def init_relationship(self, provider_url):
        if not self.provider_info:
            opc = ProviderConfigurationResponse()
            try:
                pcr = self.provider_config(provider_url,
                                           serv_pattern=UMACONF_PATTERN)
            except Exception, err:
                raise
            else:
                opc.update(pcr)

            try:
                pcr = self.provider_config(provider_url,
                                           serv_pattern=UMACONF_PATTERN)
            except Exception, err:
                raise
            else:
                opc.update(pcr)

            self.provider_info[opc["issuer"]] = opc

        if not self.client_secret:
            self.register(
                self.provider_info[provider_url]["dynamic_client_endpoint"])

    @staticmethod
    def get_uma_scope(token_type):
        if token_type in ["AAT", "PAT"]:
            return UMA_SCOPE[token_type]

    def acquire_grant(self, resource_server, token_type, userid, state="",
                      acr=PASSWORD):
        """
        Get a grant by which a PAT/AAT token can be acquired from the server

        :param resource_server: The OP to use
        :param token_type: Which kind of token to acquire
        :param userid: On behalf of which user
        :param state:
        :param acr: Authentication Context Reference
        """

        if userid not in self.token:
            self.token[userid] = {}
            token_type = "AAT"  # The first one I must have
        elif token_type == "RPT" and not "AAT" in self.token[userid]:
            token_type = "AAT"  # Must have AAT first

        self.init_relationship(resource_server)

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

        # Authenticate using HTTP basic authn
        http_args = self.client_authn_method[
            "client_secret_basic"](self).construct(
                {}, request_args=request_args, user=urllib.quote(userid),
                password="hemligt")

        return self.do_authorization_request(request_args=request_args,
                                             http_args=http_args)

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

        if not uid:
            uid = atresp["id_token"]["sub"]

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
        url = self.provider_info.values()[0]["authorization_request_endpoint"]
        return self.send(url, "POST", **kwargs)

    def create_rpt_request(self, user):
        _aat = self.token[user]["AAT"]["access_token"]
        kwargs = {"headers": {"Authorization": "Bearer %s" % _aat}}
        return kwargs

    def get_rpt(self, user):
        kwargs = self.create_rpt_request(user)
        url = self.provider_info.values()[0]["rpt_endpoint"]
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

    def match_preferences(self, pcr=None, issuer=None):
        pass

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
