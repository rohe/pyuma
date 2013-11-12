import logging
import socket
from urlparse import parse_qs

from cherrypy import wsgiserver
from mako.lookup import TemplateLookup
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.authn_context import PASSWORD
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authn.user import BasicAuthn
from oic.utils.authz import Implicit
from oic.utils.http_util import Response
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import BadRequest
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
COOKIE_NAME = "uma_as"
KEYS = {
    "RSA": {
        "key": "as.key",
        "usage": ["enc", "sig"]
    }
}

CookieHandler = CookieDealer(None)


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

ROOT = './'
LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')


def chose_permissions(environ, session):
    try:
        _user = session["user"]
    except KeyError:
        return authenticate(environ, session, "chose_permissions")

    rs_list = AUTHZSRV.resource_sets_by_user(_user)

    if len(rs_list) == 1:
        cval = {"user": _user, "authn": PASSWORD}
        headers = [CookieHandler.create_cookie("%s" % (cval,), "sso",
                                               COOKIE_NAME)]
        resp = Response(mako_template="permissions.mako",
                        template_lookup=LOOKUP,
                        headers=headers)

        rs = rs_list[0]
        argv = {
            "rsname": rs["name"],
            "scopes": rs["scopes"],
            "checked": {},
            "action": "permreg",
            "entity_id": SPS[0][1],
            "method": "get",
            #"user": _user
        }

        return resp, argv
    else:
        # have to chose resource set first
        pass


def set_permission(environ, session):
    query = parse_qs(environ["QUERY_STRING"])
    try:
        _user = query["user"][0]
    except KeyError:
        try:
            _user = session["user"]
        except KeyError:
            try:
                authn_info = environ["HTTP_AUTHORIZATION"]
                ident = BasicAuthn(AUTHZSRV, PASSWD).authenticated_as(
                    authorization=authn_info)
                _user = ident["uid"]
            except KeyError:
                return authenticate(environ, session, "set_permission")

    AUTHZSRV.store_permission(_user, query["sp_entity_id"][0],
                              query["rsname"][0], query["perm"])
    return Response("Succeeded"), {}


def authenticate(environ, session, operation):
    resp = Response(mako_template="login.mako",
                    template_lookup=LOOKUP,
                    headers=[])

    argv = {
        "action": "authn",
        "operation": operation,
        "login": "",
        "password": ""
    }
    return resp, argv


def authn(environ, session):

    # verify the username+password
    if environ["REQUEST_METHOD"] == "POST":
        query = parse_qs(get_body(environ))
    else:  # Assume environ["REQUEST_METHOD"] == "GET"
        query = parse_qs(environ["QUERY_STRING"])

    try:
        assert PASSWD[query["login"][0]] == query["password"][0]
    except (KeyError, AssertionError):
        return Unauthorized(), {}

    session["user"] = query["login"][0]
    try:
        op = query["operation"][0]
        if op == "chose_permissions":
            return chose_permissions(environ, session)
        elif op == "set_permission":
            return set_permission(environ, session)
        else:
            return BadRequest("Unknown function")
    except KeyError:
        pass

    return Response(), {}

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
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    request = environ["QUERY_STRING"]
    return AUTHZSRV.authorization_endpoint(request, authn=authn_info)


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
    path = environ.get('PATH_INFO', '').lstrip('/')

    session = {}
    try:
        cookie = environ["HTTP_COOKIE"]
        _tmp = CookieHandler.get_cookie_value(cookie, COOKIE_NAME)
        if _tmp:
            # 3-tuple (val, timestamp, type)
            session = eval(_tmp[0])
    except KeyError:
        pass

    argv = {}
    if path == "robots.txt":
        resp = static(environ, session, "static/robots.txt")
    elif path.startswith("static/"):
        resp = static(environ, session, path)
    elif path == "permission":
        resp, argv = chose_permissions(environ, session)
    elif path == "permreg":
        resp, argv = set_permission(environ, session)
    elif path == "authn":
        resp, argv = authn(environ, session)
    else:
        query = parse_qs(environ["QUERY_STRING"])
        prepath = path.split("/")[0]
        if path in [".well-known/openid-configuration",
                    ".well-known/uma-configuration"]:
            resp = provider_configuration(environ, session)
        else:
            resp = None
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

    return resp(environ, start_response, **argv)

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
    "linda.lindgren@example.com": "krall",
    "hans.granberg@example.org": "thetake",
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

from saml2 import saml
from saml2 import md
from saml2.extension import dri
from saml2.extension import idpdisc
from saml2.extension import mdattr
from saml2.extension import mdrpi
from saml2.extension import mdui
from saml2.extension import shibmd
from saml2.extension import ui
import xmldsig
import xmlenc

from saml2.mdstore import MetaDataFile

ONTS = {
    saml.NAMESPACE: saml,
    mdui.NAMESPACE: mdui,
    mdattr.NAMESPACE: mdattr,
    mdrpi.NAMESPACE: mdrpi,
    dri.NAMESPACE: dri,
    ui.NAMESPACE: ui,
    idpdisc.NAMESPACE: idpdisc,
    md.NAMESPACE: md,
    xmldsig.NAMESPACE: xmldsig,
    xmlenc.NAMESPACE: xmlenc,
    shibmd.NAMESPACE: shibmd
}


def get_sp(item):
    metad = MetaDataFile(ONTS.values(), item, item)
    metad.load()
    sps = []
    for entid, item in metad.entity.items():
        if "spsso_descriptor" in item:
            for sp in item["spsso_descriptor"]:
                _name = ""
                try:
                    for ee in sp["extensions"]["extension_elements"]:
                        if ee["__class__"] == "%s&UIInfo" % mdui.NAMESPACE:
                            _name = ee["description"][0]["text"]
                except KeyError:
                    pass
                if not _name:
                    try:
                        _name = item["organization"][
                            "organization_display_name"][0]["text"]
                    except KeyError:
                        try:
                            _name = item["organization"][
                                "organization_name"][0]["text"]
                        except KeyError:
                            try:
                                _name = item["organization"][
                                    "organization_url"][0]["text"]
                            except KeyError:
                                pass
                sps.append((_name, entid))
    return sps


class BasicAuthnExtra(BasicAuthn):
    def __init__(self, srv, symkey):
        BasicAuthn.__init__(self, srv, None, 0)
        self.symkey = symkey

    def verify_password(self, user, password):
        assert password == "hemligt"


if __name__ == '__main__':
    SPS = get_sp("./sp/sp.xml")
    # The UMA AS
    AB = AuthnBroker()
    AB.add("linda", DummyAuthn(None, "linda.lindgren@example.com"))
    AB.add("hans", DummyAuthn(None, "hans.granberg@example.org"))
    AB.add(PASSWORD, BasicAuthnExtra(None, PASSWD), 10,
           "http://%s" % socket.gethostname())

    AUTHZSRV = authzsrv.OIDCUmaAS(BASE, SessionDB(), CDB, AB, USERINFO, AUTHZ,
                                  verify_client, "1234567890", keyjar=None,
                                  configuration=AS_CONF,
                                  base_url=BASE)

    CookieHandler.init_srv(AUTHZSRV)
    init_keyjar(AUTHZSRV, KEYS, "static/jwk_as.json")

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', PORT), application)

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
