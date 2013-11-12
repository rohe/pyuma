import urllib
from oic.oauth2 import rndstr
from oic.oauth2.exception import MissingSession
from oic.oic.consumer import Consumer
from oic.utils.authn.authn_context import PASSWORD
from uma.message import AuthorizationDataRequest, RPTResponse
from uma import UMAError

__author__ = 'rolandh'


class ConnectionFailure(Exception):
    pass


UMA_SCOPE = {
    "AAT": "http://docs.kantarainitiative.org/uma/scopes/authz.json",
    "PAT": "http://docs.kantarainitiative.org/uma/scopes/prot.json",
}

UMACONF_PATTERN = "%s/.well-known/uma-configuration"

DEF_SIGN_ALG = {"id_token": "RS256",
                "openid_request_object": "RS256",
                "client_secret_jwt": "HS256",
                "private_key_jwt": "HS256"}


class Client(Consumer):
    """ An UMA client implementation

    """
    #noinspection PyUnusedLocal
    def __init__(self, session_db, client_config=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope=""):

        config = {"authz_page": authz_page,
                  "response_type": response_type,
                  "scope": scope}

        Consumer.__init__(self, session_db, config,
                          client_config=client_config,
                          server_info=server_info)

        self.provider_info = {}
        # token per user
        self.token = {}
        self.behaviour = {"require_signed_request_object":
                              DEF_SIGN_ALG["openid_request_object"]}

        self.registration_info = registration_info
        self.allow = {}
        self.registration_response = None
        self.registration_expires = 0
        self.registration_access_token = ""
        self.state = {}
        self.keyjar = None
        self.client_id = ""
        self.client_secret = ""

    def init_relationship(self, provider_url):
        if not self.provider_info:
            try:
                _ = self.provider_config(provider_url,
                                         serv_pattern=UMACONF_PATTERN)
            except Exception, err:
                raise

        if not self.client_secret:
            self.register(
                self.provider_info[provider_url]["dynamic_client_endpoint"])

    @staticmethod
    def get_uma_scope(token_type):
        if token_type in ["AAT", "PAT"]:
            return UMA_SCOPE[token_type]

    def acquire_grant(self, resource_server, token_type, userid, state=""):
        """
        Get a grant by which a PAT/AAT token can be acquired from the server

        :param resource_server: The OP to use
        :param token_type: Which kind of token to acquire
        :param userid: On behalf of which user
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
                        "acr_values": [PASSWORD]}

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

    def authorization_data_request(self, userid, ticket):
        adr = AuthorizationDataRequest(ticket=ticket,
                                       rpt=self.token[userid]["RPT"])
        _aat = self.token[userid]["AAT"]["access_token"]
        kwargs = {"headers": {"Authorization": "Bearer %s" % _aat},
                  "data": adr.to_json()}
        url = self.provider_info.values()[0]["authorization_request_endpoint"]
        return self.send(url, "POST", **kwargs)

    def get_rpt(self, user):
        _aat = self.token[user]["AAT"]["access_token"]
        kwargs = {"headers": {"Authorization": "Bearer %s" % _aat}}
        url = self.provider_info.values()[0]["rpt_endpoint"]
        resp = self.send(url, "POST", **kwargs)

        if resp.status_code == 200:
            rptr = RPTResponse().from_json(resp.text)
            self.token[user]["RPT"] = rptr["rpt"]
        else:
            raise UMAError(resp.reason)