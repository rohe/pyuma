#!/usr/bin/env python
import base64
import hashlib
import logging
import requests

from urlparse import parse_qs
from cherrypy import wsgiserver

from oic.oauth2.message import AuthorizationResponse
from oic.utils.http_util import Response
from oic.utils.http_util import Forbidden
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import InvalidCookieSign
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import NotFound
from oic.utils.http_util import ServiceError

from uma.message import PermissionRegistrationResponse
from uma.resourcesrv import Unknown
from uma.saml2uma import ErrorResponse
from uma.resourcesrv import UnknownAuthzSrv
from uma.json_resource_server import JsonResourceServer
import uma_rs

__author__ = 'rolandh'

logger = logging.getLogger("")
LOGFILE_NAME = 'uma_rs.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")
hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)

# -----------------------------------------------------------------------------

KEYS = {
    "RSA": {
        "key": "as.key",
        "usage": ["enc", "sig"]
    }
}

RES_SRV = None
CookieHandler = CookieDealer(None)
COOKIE_NAME = "rs_uma"
DATASET = None

# -----------------------------------------------------------------------------


def get_body(environ):
    length = int(environ["CONTENT_LENGTH"])
    try:
        body = environ["wsgi.input"].read(length)
    except Exception, excp:
        logger.exception("Exception while reading post: %s" % (excp,))
        raise

    # restore what I might have upset
    from StringIO import StringIO
    environ['wsgi.input'] = StringIO(body)

    return body

# -----------------------------------------------------------------------------
# Callbacks
# -----------------------------------------------------------------------------

CTYPE_MAP = {
    "ico": "image/x-icon",
    "html": "text/html",
    "json": 'application/json',
    "txt": 'text/plain',
    "css": 'text/css',
    "xml": "text/xml",
    "js": "text/javascript"
}


#noinspection PyUnusedLocal
def static(environ, session, path):
    logger.info("[static]sending: %s" % (path,))

    try:
        text = open(path).read()
        ext = path.rsplit(".", 1)[-1]
        try:
            ctype = CTYPE_MAP[ext]
        except KeyError:
            ctype = CTYPE_MAP["txt"]

        return Response(text, content=ctype)
    except IOError:
        return NotFound()

# ........................................................................


def opbyuid(environ, start_response):
    resp = Response(mako_template="opbyuid.mako",
                    template_lookup=uma_rs.LOOKUP,
                    headers=[])

    return resp(environ, start_response)


# =============================================================================

def application(environ, start_response):
    session = {}
    try:
        cookie = environ["HTTP_COOKIE"]
        try:
            _tmp = CookieHandler.get_cookie_value(cookie, COOKIE_NAME)
        except InvalidCookieSign:
            pass
        else:
            if _tmp:
                session = eval(_tmp[0])
    except KeyError:
        pass

    path = environ.get('PATH_INFO', '').lstrip('/')

    logger.info("PATH: %s" % path)
    if session:
        logger.info("Session: %s" % (session,))

    if path == "robots.txt":
        return static(environ, session, "static/robots.txt")
    elif path.startswith("static/"):
        return static(environ, session, path)

    try:
        query = parse_qs(environ["QUERY_STRING"])
    except KeyError:
        query = None

    if query:
        logger.info("Query: %s" % (query,))

    if path == "":
        return opbyuid(environ, start_response)
    elif path == "rp":
        link = acr = ""
        if "uid" in query:
            try:
                link = RES_SRV.find_srv_discovery_url(resource=query["uid"][0])
            except requests.ConnectionError:
                resp = ServiceError("Webfinger lookup failed, connection error")
                return resp(environ, start_response)
        elif "url" in query:
            link = query["url"][0]

        if "acr" in query:
            acr = query["acr"][0]

        if link:
            RES_SRV.srv_discovery_url = link
            md5 = hashlib.md5()
            md5.update(link)
            opkey = base64.b16encode(md5.digest())
            session["callback"] = True
            func = getattr(RES_SRV, "begin")
            return func(environ, start_response, session, opkey,
                        acr_value=acr)
        else:
            resp = BadRequest()
            return resp(environ, start_response)
    elif path.startswith("info"):
        try:
            owner = DATASET.get_owner(path)
        except Unknown:  # Means not owned by someone, so just return
            return DATASET.do_get(path)

        try:
            resp = RES_SRV.dataset_access(owner, environ)
        except Unknown:
            resp = BadRequest("Unknown user: %s" % owner)
            return resp(environ, start_response)
        except UnknownAuthzSrv:
            resp = BadRequest("User have not registered an authz server")
            return resp(environ, start_response)
        except KeyError, err:
            resp = BadRequest("Missing info: %s" % err)
            return resp(environ, start_response)

        # either a ErrorResponse or a ResourceResponse
        if isinstance(resp, ErrorResponse):
            try:
                resp.verify()
            except Exception:
                resp = ServiceError()
                return resp(environ, start_response)

            headers = []
            for var in ["as_uri", "host_id", "error"]:
                try:
                    headers.append((var, str(resp[var])))
                except KeyError:
                    pass

            if "ticket" in resp:
                prr = PermissionRegistrationResponse(ticket=resp["ticket"])
                resp = Forbidden(prr.to_json(), headers=headers,
                                 content="application/json")
            else:
                resp = Unauthorized(headers=headers)
        else:  # Got some permission, let the data set do it's thing
            try:
                resp = DATASET.do(resp["permissions"], path, environ)
            except Exception:
                resp = BadRequest()
                return resp(environ, start_response)

        return resp(environ, start_response)

    resp = None
    if path in RES_SRV.oic_client:
        # back after the authorization at the AS
        # Should provide an authorization code which means I can get the access
        # token
        aresp = AuthorizationResponse().from_urlencoded(environ["QUERY_STRING"])
        _cli = RES_SRV.oic_client[path]
        uid = _cli.acquire_access_token(aresp, "PAT")
        session["userid"] = uid

        # The RS registering Alice's resources
        RES_SRV.authz_registration(uid, _cli.token[uid]["PAT"],
                                   _cli.provider_info.keys()[0],
                                   path)
        # get user info
        #_pat = _cli.token[uid]["PAT"]
        #uinfo = _cli.do_user_info_request(request="openid email contact",
        #                                  token=_pat["access_token"],
        #                                  behavior="use_authorization_header",
        #                                  token_type=_pat["token_type"])
        # build resource_set_description

        descs = DATASET.build_resource_set_description(uid)
        logger.info("Resource set descriptions: %s" % (descs,))
        for desc in descs:
            try:
                RES_SRV.register_resource_set_description(uid, desc.to_json(),
                                                          uid)
            except Exception, err:
                raise

        resp = Response("OK")

    if not resp:
        logger.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")

    return resp(environ, start_response)

# -----------------------------------------------------------------------------


if __name__ == '__main__':
    #parser = argparse.ArgumentParser()
    #parser.add_argument(dest="config")
    #args = parser.parse_args()
    #
    #sys.path.insert(0, ".")

    PORT = 8089
    HOST = "https://localhost:%s" % PORT

    SERVER_CERT = "pki/server.crt"
    SERVER_KEY = "pki/server.key"
    CA_BUNDLE = None
    ROOT = "resources"

    DATASET = JsonResourceServer(ROOT, "info", HOST)

    # The UMA RS
    RES_SRV = uma_rs.main(HOST, CookieHandler)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', PORT), application)

    if HOST.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            SERVER_CERT, SERVER_KEY, CA_BUNDLE)

    #logger.info("RP server starting listening on port:%s" % rp_conf.PORT)
    print "RS started, listening on port:%s" % PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
