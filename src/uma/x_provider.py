import socket
import logging
import traceback
import urllib
import urlparse
import json

from oic.oauth2 import provider
from oic.oauth2 import MessageException
from oic.oauth2 import rndstr
from oic.oic import ClientRegistrationErrorResponse
from oic.oic import RegistrationResponse
from oic.oic import RegistrationRequest
from oic.oic.provider import secret
from oic.utils.http_util import Response
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from oic.utils.time_util import utc_time_sans_frac
from requests import ConnectionError
import sys
from uma.message import ProviderConfiguration

__author__ = 'rolandh'

logger = logging.getLogger(__name__)
STR = 5 * "_"


class Provider(provider.Provider):
    def __init__(self, name, sdb, cdb, authn_broker, authz,
                 client_authn, symkey, urlmap=None, keyjar=None,
                 hostname="", configuration=None):
        provider.Provider.__init__(self, name, sdb, cdb, authn_broker, authz,
                                   client_authn, symkey=symkey, urlmap=urlmap)

        self.baseurl = ""
        if keyjar:
            self.keyjar = keyjar
        else:
            self.keyjar = KeyJar()

        self.hostname = hostname or socket.gethostname
        self.jwks_uri = []
        self.endpoints = [DynamicClientEndpoint, TokenEndpoint,
                          AuthorizationEndpoint, UserEndpoint,
                          ResourceSetRegistrationEndpoint,
                          IntrospectionEndpoint, RPTEndpoint,
                          PermissionRegistrationEndpoint]


    def set_authn_broker(self, authn_broker):
        self.authn_broker = authn_broker
        for meth in self.authn_broker:
            meth.srv = self
        if authn_broker:
            self.cookie_func = authn_broker[0].create_cookie
        else:
            self.cookie_func = None

    @staticmethod
    def _verify_url(url, urlset):
        part = urlparse.urlparse(url)

        for reg, qp in urlset:
            _part = urlparse.urlparse(reg)
            if part.scheme == _part.scheme and part.netloc == _part.netloc:
                return True

        return False

    def do_client_registration(self, request, client_id, ignore=None):
        if ignore is None:
            ignore = []

        _cinfo = self.cdb[client_id].copy()
        logger.debug("_cinfo: %s" % _cinfo)

        for key, val in request.items():
            if key not in ignore:
                _cinfo[key] = val

        if "redirect_uris" in request:
            ruri = []
            for uri in request["redirect_uris"]:
                if urlparse.urlparse(uri).fragment:
                    err = ClientRegistrationErrorResponse(
                        error="invalid_configuration_parameter",
                        error_description="redirect_uri contains fragment")
                    return Response(err.to_json(),
                                    content="application/json",
                                    status="400 Bad Request")
                base, query = urllib.splitquery(uri)
                if query:
                    ruri.append((base, urlparse.parse_qs(query)))
                else:
                    ruri.append((base, query))
            _cinfo["redirect_uris"] = ruri

        if "sector_identifier_uri" in request:
            si_url = request["sector_identifier_uri"]
            try:
                res = self.server.http_request(si_url)
            except ConnectionError, err:
                logger.error("%s" % err)
                return self._error_response(
                    "invalid_configuration_parameter",
                    descr="Couldn't open sector_identifier_uri")

            if not res:
                return self._error_response(
                    "invalid_configuration_parameter",
                    descr="Couldn't open sector_identifier_uri")

            logger.debug("sector_identifier_uri => %s" % res.text)

            try:
                si_redirects = json.loads(res.text)
            except ValueError:
                return self._error_response(
                    "invalid_configuration_parameter",
                    descr="Error deserializing sector_identifier_uri content")

            if "redirect_uris" in request:
                logger.debug("redirect_uris: %s" % request["redirect_uris"])
                for uri in request["redirect_uris"]:
                    try:
                        assert uri in si_redirects
                    except AssertionError:
                        return self._error_response(
                            "invalid_configuration_parameter",
                            descr="redirect_uri missing from sector_identifiers"
                        )

            _cinfo["si_redirects"] = si_redirects
            _cinfo["sector_id"] = si_url
        elif "redirect_uris" in request:
            if len(request["redirect_uris"]) > 1:
                # check that the hostnames are the same
                host = ""
                for url in request["redirect_uris"]:
                    part = urlparse.urlparse(url)
                    _host = part.netloc.split(":")[0]
                    if not host:
                        host = _host
                    else:
                        try:
                            assert host == _host
                        except AssertionError:
                            return self._error_response(
                                "invalid_configuration_parameter",
                                descr=
                                "'sector_identifier_uri' must be registered")

        for item in ["policy_url", "logo_url"]:
            if item in request:
                if self._verify_url(request[item], _cinfo["redirect_uris"]):
                    _cinfo[item] = request[item]
                else:
                    return self._error_response(
                        "invalid_configuration_parameter",
                        descr="%s pointed to illegal URL" % item)

        try:
            self.keyjar.load_keys(request, client_id)
            try:
                logger.debug("keys for %s: [%s]" % (
                    client_id,
                    ",".join(["%s" % x for x in self.keyjar[client_id]])))
            except KeyError:
                pass
        except Exception, err:
            logger.error("Failed to load client keys: %s" % request.to_dict())
            err = ClientRegistrationErrorResponse(
                error="invalid_configuration_parameter",
                error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="400 Bad Request")

        return _cinfo

    @staticmethod
    def comb_redirect_uris(args):
        if "redirect_uris" not in args:
            return

        val = []
        for base, query in args["redirect_uris"]:
            if query:
                val.append("%s?%s" % (base, query))
            else:
                val.append(base)

        args["redirect_uris"] = val

    #noinspection PyUnusedLocal
    def l_registration_endpoint(self, request, authn=None, **kwargs):
        _log_debug = logger.debug
        _log_info = logger.info

        _log_debug("@registration_endpoint")

        request = RegistrationRequest().deserialize(request, "json")

        _log_info("registration_request:%s" % request.to_dict())
        resp_keys = request.keys()

        try:
            request.verify()
        except MessageException, err:
            if "type" not in request:
                return self._error(error="invalid_type",
                                   descr="%s" % err)
            else:
                return self._error(error="invalid_configuration_parameter",
                                   descr="%s" % err)

        _keyjar = self.server.keyjar

        # create new id och secret
        client_id = rndstr(12)
        while client_id in self.cdb:
            client_id = rndstr(12)

        client_secret = secret(self.seed, client_id)

        _rat = rndstr(32)
        reg_enp = ""
        for endp in self.endpoints:
            if isinstance(endp, DynamicClientEndpoint):
                reg_enp = "%s%s" % (self.baseurl, endp.etype)

        self.cdb[client_id] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "registration_access_token": _rat,
            "registration_client_uri": "%s?client_id=%s" % (reg_enp, client_id),
            "client_secret_expires_at": utc_time_sans_frac() + 86400,
            "client_id_issued_at": utc_time_sans_frac()}

        self.cdb[_rat] = client_id

        _cinfo = self.do_client_registration(request, client_id,
                                             ignore=["redirect_uris",
                                                     "policy_url",
                                                     "logo_url"])
        if isinstance(_cinfo, Response):
            return _cinfo

        args = dict([(k, v) for k, v in _cinfo.items()
                     if k in RegistrationResponse.c_param])

        self.comb_redirect_uris(args)
        response = RegistrationResponse(**args)

        self.keyjar.load_keys(request, client_id)

        # Add the key to the keyjar
        if client_secret:
            _kc = KeyBundle([{"kty": "oct", "key": client_secret,
                              "use": "ver"},
                             {"kty": "oct", "key": client_secret,
                              "use": "sig"}])
            try:
                _keyjar[client_id].append(_kc)
            except KeyError:
                _keyjar[client_id] = [_kc]

        self.cdb[client_id] = _cinfo
        _log_info("Client info: %s" % _cinfo)

        logger.debug("registration_response: %s" % response.to_dict())

        return Response(response.to_json(), content="application/json",
                        headers=[("Cache-Control", "no-store")])

    def registration_endpoint(self, request, authn=None, **kwargs):
        return self.l_registration_endpoint(request, authn, **kwargs)

    def read_registration(self, authn, request, **kwargs):
        """
        Read all information this server has on a client.
        Authorization is done by using the access token that was return as
        part of the client registration result.

        :param authn: The Authorization HTTP header
        :param request: The query part of the URL
        :param kwargs: Any other arguments
        :return:
        """

        logger.debug("authn: %s, request: %s" % (authn, request))

        # verify the access token, has to be key into the client information
        # database.
        assert authn.startswith("Bearer ")
        token = authn[len("Bearer "):]

        client_id = self.cdb[token]

        # extra check
        _info = urlparse.parse_qs(request)
        assert _info["client_id"][0] == client_id

        logger.debug("Client '%s' reads client info" % client_id)
        args = dict([(k, v) for k, v in self.cdb[client_id].items()
                     if k in RegistrationResponse.c_param])

        self.comb_redirect_uris(args)
        response = RegistrationResponse(**args)

        return Response(response.to_json(), content="application/json",
                        headers=[("Cache-Control", "no-store")])

    #noinspection PyUnusedLocal
    def providerinfo_endpoint(self, handle="", **kwargs):
        _log_debug = logger.debug
        _log_info = logger.info

        _log_info("@providerinfo_endpoint")
        try:
            _response = self.conf_info

            #for endp in self.endpoints:
            #    _response[endp(None).name] = "%s%s" % (self.baseurl,
            # endp.etype)

            _log_info("provider_info_response: %s" % (_response.to_dict(),))

            headers = [("Cache-Control", "no-store"), ("x-ffo", "bar")]
            if handle:
                (key, timestamp) = handle
                if key.startswith(STR) and key.endswith(STR):
                    cookie = self.cookie_func(key, self.cookie_name, "pinfo",
                                              self.sso_ttl)
                    headers.append(cookie)

            resp = Response(_response.to_json(), content="application/json",
                            headers=headers)
        except Exception, err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            resp = Response(message, content="html/text")

        return resp

