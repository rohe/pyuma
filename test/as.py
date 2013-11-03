import logging
import socket
from urlparse import parse_qs
from beaker.middleware import SessionMiddleware
from beaker.session import Session
from cherrypy import wsgiserver
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.authn_context import PASSWORD
from oic.utils.authn.authn_context import UNSPECIFIED
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authn.user import BasicAuthn
from oic.utils.authz import Implicit
from oic.utils.http_util import Response
from oic.utils.http_util import NotFound
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo

from uma import authzsrv
from uma import init_keyjar

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, uid="Linda"):
        UserAuthnMethod.__init__(self, srv)
        self.user = uid

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}


AUTHZ = Implicit("PERMISSION")
CDB = {}
PORT = 8088
BASE = "http://localhost:8088"
AUTHZSRV = None
KEYS = {
    "RSA": {
        "key": "as.key",
        "usage": ["enc", "sig"]
    }
}


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
#noinspection PyUnresolvedReferences
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

        resp = Response(text, headers=[('Content-Type', ctype)])
    except IOError:
        resp = NotFound()

    return resp

# ........................................................................


#noinspection PyUnusedLocal
def dynamic_client(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    body = get_body(environ)
    return AUTHZSRV.registration_endpoint(body, authn=authn_info)


#noinspection PyUnusedLocal
def token(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    return AUTHZSRV.token_endpoint(auth_header=authn_info,
                                   request=query)


#noinspection PyUnusedLocal
def user(environ, session, query):
    return Response()


#noinspection PyUnusedLocal
def user_info(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    return AUTHZSRV.userinfo_endpoint(authn=authn_info, request=query)


#noinspection PyUnusedLocal
def resource_set_registration(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    try:
        if_match = environ["HTTP_IF_MATCH"]
    except KeyError:
        if_match = ""

    method = environ["REQUEST_METHOD"]
    return AUTHZSRV.resource_set_registration_endpoint(environ["PATH_INFO"],
                                                       method=method,
                                                       authn=authn_info,
                                                       body=query,
                                                       if_match=if_match)


#noinspection PyUnusedLocal
def introspection(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    return AUTHZSRV.introspection_endpoint(query, authn=authn_info)


#noinspection PyUnusedLocal
def permission_registration(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    return AUTHZSRV.permission_registration_endpoint(query, authn=authn_info)


#noinspection PyUnusedLocal
def rpt(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    return AUTHZSRV.rpt_endpoint(authn_info)


#noinspection PyUnusedLocal
def oidc_authorization_request(environ, session, query):
    request = environ["QUERY_STRING"]
    return AUTHZSRV.authorization_endpoint(request)


#noinspection PyUnusedLocal
def authorization_request(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    return AUTHZSRV.authorization_request_endpoint(query, authn_info)


#noinspection PyUnusedLocal
def provider_configuration(environ, session):
    return AUTHZSRV.providerinfo_endpoint()


ENDPOINT2CB = {
    "dynamic_client": dynamic_client,
    "token": token,
    "user": user,
    "resource_set": resource_set_registration,
    "introspection": introspection,
    "permission_registration": permission_registration,
    "rpt": rpt,
    "authorization_request": authorization_request,
    "authorization": oidc_authorization_request,
    "user_info": user_info,
    "userinfo": user_info,
}


def application(environ, start_response):
    session = Session(environ['beaker.session'])

    path = environ.get('PATH_INFO', '').lstrip('/')
    resp = None
    if path == "robots.txt":
        resp = static(environ, session, "static/robots.txt")
    elif path.startswith("static/"):
        resp = static(environ, session, path)

    if not resp:
        query = parse_qs(environ["QUERY_STRING"])
        prepath = path.split("/")[0]
        if path in [".well-known/openid-configuration",
                    ".well-known/uma-configuration"]:
            resp = provider_configuration(environ, session)
        else:
            for service in AUTHZSRV.services():
                if prepath == service:
                    try:
                        resp = ENDPOINT2CB[prepath](environ, session, query)
                        break
                    except Exception, err:
                        raise

    if isinstance(resp, Response):
        pass
    else:
        resp = NotImplemented(path)

    return resp(environ, start_response)

# -----------------------------------------------------------------------------

AS_CONF = {
    "version": "1.0",
    "issuer": BASE,
    "pat_profiles_supported": ["bearer"],
    "aat_profiles_supported": ["bearer"],
    "rpt_profiles_supported": ["bearer"],
    "pat_grant_types_supported": ["authorization_code"],
    "aat_grant_types_supported": ["authorization_code"],
    "claim_profiles_supported": ["openid"],
    #"dynamic_client_endpoint": "%s/dynamic_client_endpoint" % BASE,
    #"token_endpoint": "%s/token_endpoint" % BASE,
    #"user_endpoint": "%s/user_endpoint" % BASE,
    #"resource_set_registration_endpoint": "%s/rsr_endpoint" % BASE,
    #"introspection_endpoint": "%s/introspection_endpoint" % BASE,
    #"permission_registration_endpoint": "%s/pr_endpoint" % BASE,
    #"rpt_endpoint": "%s/rpt_endpoint" % BASE,
    #"authorization_request_endpoint": "%s/ar_endpoint" % BASE,
    #"userinfo_endpoint": "%s/user_info_endpoint" % BASE
    # ------------ The OIDC provider config -----------------------

}

PASSWD = {
    "linda": "krall",
    "user": "howes",
    "https://sp.example.org/": "code"
}

USERDB = {
    "hans.granberg@example.org": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "hans.granberg@example.org"
    },
    "linda.lindgren@example.com": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "linda.lindgren@example.com"
    }
}

USERINFO = UserInfo(USERDB)

if __name__ == '__main__':
    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    # The UMA AS
    AB = AuthnBroker()
    AB.add(UNSPECIFIED, DummyAuthn(None, "linda.lindgren@example.com"))
    AB.add(PASSWORD, BasicAuthn(None, PASSWD), 10,
           "http://%s" % socket.gethostname())

    AUTHZSRV = authzsrv.OIDCUmaAS(BASE, SessionDB(), CDB, AB, USERINFO, AUTHZ,
                                  verify_client, "1234567890", keyjar=None,
                                  configuration=AS_CONF,
                                  base_url=BASE)

    init_keyjar(AUTHZSRV, KEYS, "static/jwk_as.json")

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    #if BASE.startswith("https"):
    #    from cherrypy.wsgiserver import ssl_pyopenssl
    #
    #    SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
    #        SERVER_CERT, SERVER_KEY, CA_BUNDLE)

    #logger.info("RP server starting listening on port:%s" % rp_conf.PORT)
    print "AS started, listening on port:%s" % PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
