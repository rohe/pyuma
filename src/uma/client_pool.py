import logging
import traceback
import sys
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from oic.utils.http_util import Response
from oic.oauth2 import rndstr
#from oic.oauth2 import PBase
from oic.oauth2.message import ErrorResponse

from oic.oic.message import AuthorizationResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AccessTokenResponse
#from oic.utils.webfinger import WebFinger

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_NAME = "UMARS"
FLOW_TYPE = "code"  # or "token"

CLIENT_CONFIG = {}


class Pool(object):
    def __init__(self, baseurl, client_cls, pool_config=None,
                 template_lookup=None):
        """
        :param baseurl: This clients base URL, used to create callback URLs
        :param client_cls: Which Client Class to use
        :param pool_config: Configuration for the client pool
        """

        self.baseurl = baseurl
        self.flow_type = FLOW_TYPE
        self.access_token_response = AccessTokenResponse
        self.client_cls = client_cls
        self.authn_method = None

        self.pool_config = pool_config

        self.registration_info = {}
        #self.oic_client = {}
        self.client = {}
        self.template_lookup = template_lookup

    def dynamic(self, callback, session, authsrv):
        """
        :param callback: The callback URL for a specific client instance
        :param session: Session information
        :param authsrv: Authorization Server URL
        """
        try:
            client = self.client[authsrv]
        except KeyError:
            try:
                _client_conf = self.pool_config["client"][authsrv]
            except KeyError:
                _client_conf = self.pool_config["client"][""]

            client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD)
            client.redirect_uris = [callback]

            client.registration_info=_client_conf["registration_info"]
            _me = client.registration_info.copy()
            _me["redirect_uris"] = [callback]

            try:
                client.provider_info = _client_conf["provider"]
                session["provider"] = authsrv
                dce = _client_conf["provider"]["dynamic_client_endpoint"]
                issuer = authsrv
            except KeyError:
                # Dynamically read server info
                provider_conf = client.provider_config(authsrv)
                dce = provider_conf["dynamic_client_endpoint"]
                issuer = provider_conf["issuer"]
                logger.debug("Got provider config: %s" % provider_conf)
                session["provider"] = provider_conf["issuer"]

            logger.debug("Registering RP")
            reg_info = client.register(dce, **_me)
            logger.debug("Registration response: %s" % reg_info)

            try:
                client.keyjar = _client_conf["keyjar"]
            except KeyError:
                client.keyjar = self.pool_config["keyjar"]

            try:
                self.client[issuer] = client
            except KeyError:
                self.client = {issuer: client}

            # try:
            #     self.oic_client[key] = client
            # except KeyError:
            #     self.oic_client = {key: client}

        return client

    def static(self, callback, authsrv):
        try:
            client = self.client[authsrv]
            logger.debug("Static client: %s" % authsrv)
        except KeyError:
            client = self.client_cls(client_authn_method=CLIENT_AUTHN_METHOD)
            client.redirect_uris = [callback]
            _client_conf = self.pool_config["client"][authsrv]
            client.provider_info = _client_conf["provider"]

            client.client_id = _client_conf["client_id"]
            client.client_secret = _client_conf["client_secret"]

            try:
                client.keyjar = _client_conf["keyjar"]
            except KeyError:
                client.keyjar = self.pool_config["keyjar"]

            try:
                self.client[authsrv] = client
            except KeyError:
                self.client = {authsrv: client}

        return client

    def init_client(self, session, key):
        """ Instantiate a client to talk to the AS

        :param session:
        :param key:
        :return: client instance
        """
        logger.debug("FLOW type: %s" % self.flow_type)

        if self.baseurl.endswith("/"):
            callback = self.baseurl + key
        else:
            callback = "%s/%s" % (self.baseurl, key)

        try:
            _ = self.pool_config["client"][key]["client_id"]
            client = self.static(callback, key)
        except KeyError:
            client = self.dynamic(callback, session, key)

        try:
            client.state = session["state"]
        except KeyError:
            client.state = session["state"] = rndstr()

        return client

    def get_request_args(self, client, acr_value, session):
        """
        :param client: Client instance
        :param acr_value: Authentication Context reference
        :param session: Session information
        :return: A set of Authorization request arguments
        """
        request_args = {
            "response_type": self.flow_type,
            "scope": self.pool_config["scope"],
            "state": client.state,
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

        logger.info("client args: %s" % client.__dict__.items(), )
        logger.info("request_args: %s" % (request_args,))

        return client, request_args

    @staticmethod
    def construct_authorization_request(client, request_args):
        """
        :param client: Client instance
        :param request_args: Request arguments
        :return: Which URL to redirect the user to and HTTP arguments
        """

        cis = client.construct_AuthorizationRequest(
            request_args=request_args)
        logger.debug("request: %s" % cis)

        url, body, ht_args, cis = client.uri_and_body(
            AuthorizationRequest, cis, method="GET",
            request_args=request_args,
            endpoint=client.provider_info.values()[0][
                "authorization_endpoint"])
        logger.debug("body: %s" % body)


        logger.info("URL: %s" % url)
        logger.debug("ht_args: %s" % ht_args)

        return url, ht_args

    #noinspection PyUnusedLocal
    def begin(self, environ, start_response, session, key, acr_value=""):
        """Step 1: Get a access grant.

        :param environ:
        :param start_response:
        :param session:
        """
        try:
            client = self.init_client(session, key)
            # User info claims
        except Exception, exc:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(
                environ, start_response,
                (False, "Cannot find the OP! Please view your configuration."))

        session["client"] = client
        request_args = self.get_request_args(client, acr_value, session)

        try:
            url, ht_args = self.construct_authorization_request(client,
                                                                request_args)
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(environ, start_response, (
                False, "Authorization request can not be performed!"))

        logger.info("URL: %s" % url)
        logger.debug("ht_args: %s" % ht_args)

        session["client"] = client
        resp_headers = [("Location", str(url))]
        if ht_args:
            resp_headers.extend([(a, b) for a, b in ht_args.items()])
        logger.debug("resp_headers: %s" % resp_headers)
        start_response("302 Found", resp_headers)
        return []

    def get_accesstoken(self, client, authresp):
        issuer = client.provider_info.keys()[0]
        #logger.debug("state: %s (%s)" % (client.state, msg["state"]))
        key = client.keyjar.get_verify_key(owner=issuer)
        kwargs = {"key": key}
        logger.debug("key: %s" % key)

        if self.authn_method:
            kwargs["authn_method"] = self.authn_method

        # get the access token
        return client.do_access_token_request(
            state=authresp["state"], response_cls=self.access_token_response,
            **kwargs)

    #noinspection PyUnusedLocal
    @staticmethod
    def verify_token(client, access_token):
        return {}

    @staticmethod
    def get_userinfo(client, authresp, access_token, **kwargs):
        # use the access token to get some userinfo
        return client.do_user_info_request(state=authresp["state"],
                                           schema="openid",
                                           access_token=access_token,
                                           **kwargs)

    #noinspection PyUnusedLocal
    def phase_n(self, environ, query, session):
        """Step 2: Once the consumer has redirected the user back to the
        callback URL you can request the access token the user has
        approved.

        :param environ: WGSI environ
        :param query: The query part of the request URL
        :param session: Session information
        :return: Tuple of (status, userinfo, access_token, client)
        """

        client = session["client"]
        logger.debug("info: %s" % query)
        logger.debug("keyjar: %s" % client.keyjar)

        authresp = client.parse_response(AuthorizationResponse, query,
                                         sformat="dict")

        if isinstance(authresp, ErrorResponse):
            return False, "Access denied"

        logger.debug("callback environ: %s" % environ)

        if self.flow_type == "code":
            # get the access token
            try:
                tokenresp = self.get_accesstoken(client, authresp)
            except Exception, err:
                logger.error("%s" % err)
                raise

            if isinstance(tokenresp, ErrorResponse):
                return False, "Invalid response %s." % tokenresp["error"]

            access_token = tokenresp["access_token"]
        else:
            access_token = authresp["access_token"]

        userinfo = self.verify_token(client, access_token)

        inforesp = self.get_userinfo(client, authresp, access_token)

        if isinstance(inforesp, ErrorResponse):
            return False, "Invalid response %s." % inforesp["error"], session

        userinfo.update(inforesp.to_dict())

        logger.debug("UserInfo: %s" % inforesp)

        return True, userinfo, access_token, client

    #noinspection PyUnusedLocal
    def callback(self, environ, start_response, query, session):
        """
        This is where we come back after the OP has done the
        Authorization Request.

        :param environ:
        :param start_response:
        :param query:
        :param session:
        :return:
        """
        _service = self.__class__.__name__

        logger.debug("[do_%s] environ: %s" % (_service, environ))
        logger.debug("[do_%s] query: %s" % (_service, query))

        try:
            result = self.phase_n(environ, query, session)
            logger.debug("[do_%s] response: %s" % (_service, result))
        except Exception:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            result = (False, "An unknown exception has occurred.")

        return self.result(environ, start_response, result)

    def result(self, environ, start_response, result):
        resp = Response(mako_template="opresult.mako",
                        template_lookup=self.template_lookup,
                        headers=[])
        argv = {
            "result": result
        }
        return resp(environ, start_response, **argv)

    # def find_srv_discovery_url(self, resource):
    #     """
    #     Use Webfinger to find the OP, The input is a unique identifier
    #     of the user. Allowed forms are the acct, mail, http and https
    #     urls. If no protocol specification is given like if only an
    #     email like identifier is given. It will be translated if possible to
    #     one of the allowed formats.
    #
    #     :param resource: unique identifier of the user.
    #     :return:
    #     """
    #
    #     try:
    #         args = {"ca_certs": self.extra["ca_bundle"]}
    #     except KeyError:
    #         args = {}
    #     wf = WebFinger(httpd=PBase(**args))
    #     return wf.discovery_query(resource)
