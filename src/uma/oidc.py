import importlib
import logging
import traceback
import sys
from oic.utils.authn.client import CLIENT_AUTHN_METHOD

from oic.utils.http_util import Response
from oic.oauth2 import rndstr
from oic.oauth2 import PBase
from oic.oauth2.message import ErrorResponse

from oic.oic.message import AuthorizationResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AccessTokenResponse
from oic.utils.webfinger import WebFinger
#from uma.message import ProviderConfiguration
from uma.client import Client
__author__ = 'rolandh'

logger = logging.getLogger(__name__)


def token_secret_key(sid):
    return "token_secret_%s" % sid


SERVICE_NAME = "OIC"
FLOW_TYPE = "code"  # or "token"

CLIENT_CONFIG = {}


class OpenIDConnect(object):
    def __init__(self, config=None, config_file="", baseurl="", **kwargs):
        self.client_id = self.client_secret = ""
        for param in ["client_id", "client_secret"]:
            try:
                setattr(self, param, kwargs[param])
                del kwargs[param]
            except KeyError:
                pass

        self.extra = kwargs
        try:
            self.srv_discovery_url = kwargs["srv_discovery_url"]
        except KeyError:
            self.srv_discovery_url = None
        self.flow_type = FLOW_TYPE
        self.access_token_response = AccessTokenResponse
        self.client_cls = Client
        self.authn_method = None

        if config_file:
            conf = importlib.import_module(config_file)
        else:
            conf = config

        self.registration_info = {}
        self.baseurl = baseurl
        self.scope = ""
        self.template_lookup = None

        for k, v in conf.items():
            if not k.startswith("__"):
                setattr(self, k, v)

        self.oic_client = {}
        self.client = {}

    def dynamic(self, callback, session, key):
        try:
            client = self.oic_client[key]
        except KeyError:
            client = self.client_cls(
                {},
                client_config={"client_authn_method": CLIENT_AUTHN_METHOD},
                registration_info=self.registration_info)

            client.redirect_uris = [callback]
            _me = self.registration_info.copy()
            _me["redirect_uris"] = [callback]

            provider_conf = client.provider_config(self.srv_discovery_url)
            logger.debug("Got provider config: %s" % provider_conf)
            session["provider"] = provider_conf["issuer"]
            logger.debug("Registering RP")
            reg_info = client.register(provider_conf["dynamic_client_endpoint"],
                                       **_me)
            logger.debug("Registration response: %s" % reg_info)
            for prop in ["client_id", "client_secret"]:
                try:
                    setattr(client, prop, reg_info[prop])
                except KeyError:
                    pass
            try:
                self.client[provider_conf["issuer"]] = client
            except KeyError:
                self.client = {provider_conf["issuer"]: client}

            try:
                self.oic_client[key] = client
            except KeyError:
                self.oic_client = {key: client}

        return client

    def static(self, callback, key):
        try:
            client = self.oic_client[key]
            logger.debug("Static client: %s" % self.oic_client)
        except KeyError:
            client = self.client_cls(
                {},
                client_config={"client_authn_method": CLIENT_AUTHN_METHOD},
                registration_info=self.registration_info)
            client.redirect_uris = [callback]
            for typ in ["authorization", "token", "userinfo"]:
                endpoint = "%s_endpoint" % typ
                setattr(client, endpoint, self.extra[endpoint])

            client.client_id = self.client_id
            client.client_secret = self.client_secret

            if "keys" in self.extra:
                client.keyjar.add(self.extra["keys"][0], self.extra["keys"][1])

            try:
                self.oic_client[key] = client
            except KeyError:
                self.oic_client = {key: client}
        return client

    #noinspection PyUnusedLocal
    def begin(self, environ, start_response, session, key, acr_value=""):
        """Step 1: Get a access grant.

        :param environ:
        :param start_response:
        :param session:
        """
        try:
            logger.debug("FLOW type: %s" % self.flow_type)

            if self.baseurl.endswith("/"):
                callback = self.baseurl + key
            else:
                callback = "%s/%s" % (self.baseurl, key)

            if self.srv_discovery_url:
                client = self.dynamic(callback, session, key)
            else:
                client = self.static(callback, key)
            try:
                client.state = session["state"]
            except KeyError:
                client.state = session["state"] = rndstr()

            request_args = {
                "response_type": self.flow_type,
                "scope": self.scope,
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
            # User info claims
        except Exception, exc:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            return self.result(
                environ, start_response,
                (False, "Cannot find the OP! Please view your configuration."))

        try:
            cis = client.construct_AuthorizationRequest(
                request_args=request_args)
            logger.debug("request: %s" % cis)

            url, body, ht_args, cis = client.uri_and_body(
                AuthorizationRequest, cis, method="GET",
                request_args=request_args,
                endpoint=client.provider_info.values()[0][
                    "authorization_endpoint"])
            logger.debug("body: %s" % body)
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
        if self.srv_discovery_url:
            issuer = client.provider_info.keys()[0]
            #logger.debug("state: %s (%s)" % (client.state, msg["state"]))
            key = client.keyjar.get_verify_key(owner=issuer)
            kwargs = {"key": key}
            logger.debug("key: %s" % key)
        else:
            kwargs = {"keyjar": client.keyjar}

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

        try:
            args = {"ca_certs": self.extra["ca_bundle"]}
        except KeyError:
            args = {}
        wf = WebFinger(httpd=PBase(**args))
        return wf.discovery_query(resource)