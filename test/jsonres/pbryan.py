#!/usr/bin/env python
import base64
import hashlib
import json
import logging
from mako.lookup import TemplateLookup
from oic.utils.authn.user import UsernamePasswordMako
import requests

from urlparse import parse_qs
from cherrypy import wsgiserver

from oic.oauth2.message import Message
from oic.oauth2.message import AuthorizationResponse
from oic.utils.http_util import Response, Redirect
from oic.utils.http_util import Forbidden
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import NotFound
from oic.utils.http_util import ServiceError

from uma.message import PermissionRegistrationResponse
from uma.resourcesrv import Unknown
from uma.saml2uma import ErrorResponse
from uma.resourcesrv import UnknownAuthzSrv
import json_rs

__author__ = 'rolandh'

logger = logging.getLogger("")
LOGFILE_NAME = 'rs.log'
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
AUTHN = None

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
                    template_lookup=LOOKUP,
                    headers=[])

    return resp(environ, start_response)


# =============================================================================

def application(environ, start_response):
    session = environ['beaker.session']

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

    resp = None

    if path == "" or path == "intro":
        try:
            _ = session["uid"]
        except KeyError:
            session["return_to"] = "intro"
            resp = AUTHN(extra=["title", "host"], title="RS Authentication",
                         host="the JSON resource server")
            return resp(environ, start_response)

        return opbyuid(environ, start_response)
    elif path == "verify":
        if not query:
            query = parse_qs(get_body(environ))
        resp = AUTHN.verify(query, return_to=session["return_to"])
        if isinstance(resp, Redirect):
            session["uid"] = query["login"][0]
        return resp(environ, start_response)
    elif path == "rp":  # has to be authenticated for this
        link = acr = ""
        if "uid" in query:
            if not "url" in query:
                try:
                    link = RES_SRV.find_srv_discovery_url(
                        resource=query["uid"][0])
                except requests.ConnectionError:
                    resp = ServiceError(
                        "Webfinger lookup failed, connection error")
                    return resp(environ, start_response)

        if "url" in query:
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
    elif path.startswith("info"):
        try:
            owner = RES_SRV.dataset.get_owner(path)
        except Unknown:  # Means not owned by someone, so just return
            return RES_SRV.dataset.do_get(path)

        try:
            jresp = RES_SRV.dataset_access(owner, environ, path)
        except Unknown:
            resp = BadRequest("Unknown user: %s" % owner)
            return resp(environ, start_response)
        except UnknownAuthzSrv:
            resp = BadRequest("User have not registered an authz server")
            return resp(environ, start_response)
        except KeyError, err:
            resp = BadRequest("Missing info: %s" % err)
            return resp(environ, start_response)
        except Exception, err:
            pass
        else:
            if isinstance(jresp, Message):
                resp = jresp
            else:
                resp = json.loads(jresp)

        # either a ErrorResponse or a ResourceResponse
        if "error" in resp:
            try:
                err_resp = ErrorResponse(**resp)
                err_resp.verify()
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
                resp = RES_SRV.dataset.do(path, environ, resp)
            except Exception, err:
                resp = BadRequest()
    elif path == "uma":  # Back after verified authentication
        aresp = RES_SRV.parse_authz_response(environ["QUERY_STRING"])
        # get access token
        accresp = RES_SRV.do_access_token_request()
        uid = session["uid"]
        RES_SRV.authz_registration(uid, accresp,
                                   RES_SRV.provider_info.keys()[0], "")
        if isinstance(aresp, AuthorizationResponse):
            # time to register some resource sets
            descs = RES_SRV.dataset.build_resource_set_description(uid)
            logger.info("Resource set descriptions: %s" % (descs,))
            for path, desc in descs:
                try:
                    RES_SRV.register_resource_set_description(uid,
                                                              desc.to_json(),
                                                              path)
                except Exception, err:
                    raise

            resp = Response(
                "Resource sets registered at the Authorization Service")
        else:
            resp = BadRequest(aresp.to_json(), content="application/json")
    elif path == "login":  # local login
        resp = Response("OK")
    elif path == "verify":  # verify local login
        resp = Response("OK")

    if not resp:
        logger.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")

    return resp(environ, start_response)

# -----------------------------------------------------------------------------
ROOT = './'
LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')

PASSWD = {
    "alice": "krall",
    "hans": "thetake",
    "user": "howes",
    "https://sp.example.org/": "code"
}


if __name__ == '__main__':
    #parser = argparse.ArgumentParser()
    #parser.add_argument(dest="config")
    #args = parser.parse_args()
    #
    #sys.path.insert(0, ".")
    from beaker.middleware import SessionMiddleware

    PORT = 8089
    #HOST = "https://lingon.catalogix.se:%s" % PORT
    HOST = "https://localhost:%s" % PORT

    SERVER_CERT = "../pki/server.crt"
    SERVER_KEY = "../pki/server.key"
    CA_BUNDLE = None
    ROOT = "resources"

    #DATASET = JsonResourceServer(ROOT, "info", HOST)

    AUTHN = UsernamePasswordMako(None, "login_rs.mako", LOOKUP, PASSWD,
                                 "%s/authorization" % HOST)

    # The UMA RS
    RES_SRV = json_rs.main(HOST, CookieHandler)

    AUTHN.srv = RES_SRV

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', PORT), SessionMiddleware(application, session_opts))

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
