#!/usr/bin/env python
import json
import logging
from urlparse import parse_qs

from cherrypy import wsgiserver
from oic.exception import AccessDenied
from oic.utils.authn.authn_context import PASSWORD
from oic.utils.authn.user import BasicAuthn
from oic.utils.http_util import Response, InvalidCookieSign
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import BadRequest
from oic.utils.http_util import NotFound
from oic.utils.webfinger import WebFinger, OIC_ISSUER
from uma.resource_set import UnknownObject

import azs

__author__ = 'rolandh'

logger = logging.getLogger("")
LOGFILE_NAME = 'azs.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")
hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


PORT = 8088
BASE = "https://localhost:%s" % PORT
CookieHandler = CookieDealer(None)
COOKIE_NAME = "as_uma"


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


def edit_permission_form(uid, rst, entity_id, resource_name, checked=None):
    cval = {"user": uid, "authn": PASSWORD}
    headers = [CookieHandler.create_cookie("%s" % (cval,), "sso", COOKIE_NAME)]

    resp = Response(mako_template="mult_perm.mako",
                    template_lookup=azs.LOOKUP,
                    headers=headers)
    if checked is None:
        checked = {}

    # create_choice_tree(scopes, checked, action, entity_id, method, user,
    #     rsname)
    argv = {
        "rsname": resource_name,
        "scopes": rst,
        "checked": checked,
        "action": "permreg",
        "entity_id": entity_id,
        "method": "get",
    }

    return resp, argv


def chose_permissions(environ, session):
    try:
        _user = session["user"]
    except KeyError:
        return authenticate(environ, session, "chose_permissions")

    rs_list = AUTHZSRV.resource_sets_by_user(_user)

    if len(rs_list) == 1:
        rs = rs_list[0]
        return edit_permission_form(_user, rs["name"], rs["scopes"], SPS[0][1])
    else:
        # have to chose resource set first
        pass


def validate_user(query, environ, session, op):
    try:
        _user = query["user"][0]
    except KeyError:
        try:
            _user = session["user"]
        except KeyError:
            try:
                authn_info = environ["HTTP_AUTHORIZATION"]
                ident = BasicAuthn(AUTHZSRV, azs.PASSWD).authenticated_as(
                    authorization=authn_info)
                _user = ident["uid"]
            except KeyError:
                raise AccessDenied

    return _user

def set_permission(environ, session):
    query = parse_qs(environ["QUERY_STRING"])

    try:
        _user = validate_user(query, environ, session, "set_permission")
    except AccessDenied:
        return authenticate(environ, session, "set_permission")

    perm = dict([(v, None) for v in query["perm"]])
    AUTHZSRV.store_permission(_user, query["sp_entity_id"][0], perm)
    return Response("Permission stored"), {}


def get_permissions(environ, session):
    query = parse_qs(environ["QUERY_STRING"])

    try:
        _user = validate_user(query, environ, session, "set_permission")
    except AccessDenied:
        return authenticate(environ, session, "set_permission")

    res = AUTHZSRV.read_permissions(_user, query["requestor"][0],
                                    query["rsname"][0])
    return Response(res)


def modify_permission(environ, session):
    query = parse_qs(environ["QUERY_STRING"])
    if not query:
        query = parse_qs(get_body(environ))

    try:
        _user = validate_user(query, environ, session, "set_permission")
    except AccessDenied:
        return authenticate(environ, session, "set_permission")

    checkd = AUTHZSRV.rsid_permits(_user, query["requestor"][0])

    _rsid = query["resource"][0]
    rst = AUTHZSRV.resource_set_tree_by_rsid(_rsid)

    return edit_permission_form(query["user"][0], rst, query["requestor"][0],
                                AUTHZSRV.resource_set_name(_rsid), checkd)


def delete_permissions(environ, session):
    query = parse_qs(environ["QUERY_STRING"])
    if not query:
        query = parse_qs(get_body(environ))

    try:
        _user = validate_user(query, environ, session, "set_permission")
    except AccessDenied:
        return authenticate(environ, session, "set_permission")

    AUTHZSRV.rm_permission(_user, query["requestor"][0], query["resource"][0])

    return Response("Permission removed"), {}


def authenticate(environ, session, operation):
    resp = Response(mako_template="login.mako",
                    template_lookup=azs.LOOKUP,
                    headers=[])

    argv = {
        "action": "authn",
        "operation": operation,
        "login": "",
        "password": ""
    }

    return resp, argv


def verify(environ):
    if environ["REQUEST_METHOD"] == "POST":
        query = get_body(environ)
    else:  # Assume environ["REQUEST_METHOD"] == "GET"
        query = environ["QUERY_STRING"]
    resp = AUTHZSRV.verify_endpoint(query)
    return resp, {}


def authn(environ, session):

    # verify the username+password
    if environ["REQUEST_METHOD"] == "POST":
        query = parse_qs(get_body(environ))
    else:  # Assume environ["REQUEST_METHOD"] == "GET"
        query = parse_qs(environ["QUERY_STRING"])

    try:
        assert azs.PASSWD[query["login"][0]] == query["password"][0]
    except (KeyError, AssertionError):
        return Unauthorized(), {}

    #uid = azs.UID2EPPN[query["login"][0]]
    uid = query["login"][0]
    cval = {"user": uid, "authn": PASSWORD}
    headers = [CookieHandler.create_cookie("%s" % (cval,), "sso", COOKIE_NAME)]

    session["user"] = uid
    try:
        op = query["operation"][0]
        if op == "chose_permissions":
            return chose_permissions(environ, session)
        elif op == "set_permission":
            return set_permission(environ, session)
        elif op == "manage":
            return manage(uid, headers)
        else:
            pass
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
    resp = AUTHZSRV.dynamic_client_endpoint(body, environ, authn=authn_info)
    return resp, {}


#noinspection PyUnusedLocal
def token(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    resp = AUTHZSRV.token_endpoint(auth_header=authn_info,
                                   request=query)
    #if resp.status == "200 OK":
    #    _dict = json.loads(resp.message)
    #    _idt = IdToken().from_jwt(str(_dict["id_token"]),
    #                              keyjar=AUTHZSRV.keyjar)
    #    uid = _idt["sub"]
    return resp, {}


#noinspection PyUnusedLocal
def user(environ, session, query):
    return authenticate(environ, session, "login")


#noinspection PyUnusedLocal
def user_info(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    resp = AUTHZSRV.userinfo_endpoint(authn=authn_info, request=query)
    return resp, {}


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
    resp = AUTHZSRV.resource_set_registration_endpoint(environ["PATH_INFO"],
                                                       method=method,
                                                       authn=authn_info,
                                                       body=query,
                                                       if_match=if_match)
    return resp, {}


#noinspection PyUnusedLocal
def introspection(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    resp = AUTHZSRV.introspection_endpoint(query, authn=authn_info)
    return resp, {}


#noinspection PyUnusedLocal
def permission_registration(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    resp = AUTHZSRV.permission_registration_endpoint(query, authn=authn_info)
    return resp, {}


#noinspection PyUnusedLocal
def rpt(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    resp = AUTHZSRV.rpt_endpoint(authn_info)
    return resp, {}


def replace_cookie_in_header(resp):
    if resp.headers:
        _header = []
        for header in resp.headers:
            key, val = header
            if key == "Set-Cookie":
                try:
                    # Unpack the header
                    (uid, _, typ) = CookieHandler.get_cookie_value(val,
                                                                   "pyoidc")
                    if typ == "sso":
                        #uid = azs.UID2EPPN[uid]
                        _tup = CookieHandler.create_cookie(uid, "sso", "pyoidc")
                        val = _tup[1]
                except InvalidCookieSign:
                    pass
            _header.append((key, val))
        resp.headers = _header


#noinspection PyUnusedLocal
def oidc_authorization_request(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    request = environ["QUERY_STRING"]
    try:
        _kaka = environ["HTTP_COOKIE"]
    except KeyError:
        _kaka = None
    resp = AUTHZSRV.authorization_endpoint(request, cookie=_kaka,
                                           authn=authn_info)
    #replace_cookie_in_header(resp)
    return resp, {}


#noinspection PyUnusedLocal
def authorization_request(environ, session, query):
    try:
        authn_info = environ["HTTP_AUTHORIZATION"]
    except KeyError:
        authn_info = ""
    if not query:
        query = get_body(environ)
    resp = AUTHZSRV.authorization_data_request_endpoint(query, authn_info)
    return resp, {}


#noinspection PyUnusedLocal
def openid_provider_configuration(environ, session):
    return AUTHZSRV.providerinfo_endpoint()


#noinspection PyUnusedLocal
def uma_provider_configuration(environ, session):
    return AUTHZSRV.uma_providerinfo_endpoint()


#noinspection PyUnusedLocal
def resource_set(uid):
    res_set = AUTHZSRV.resource_sets_by_user(uid)
    # returns list of ResourceSetDescription instances
    _result = [{"name": r["name"],
                "id": AUTHZSRV.map_id_rsid[r["_id"]]} for r in res_set]
    resp = Response(json.dumps(_result))
    return resp, {}


#noinspection PyUnusedLocal
def permits(uid):
    _result = AUTHZSRV.permits_by_user(uid)
    # returns a dictionary with requestors as keys and list of resource_ids
    # as values
    resp = Response(json.dumps(_result))
    return resp, {}


def webfinger(environ):
    query = parse_qs(environ["QUERY_STRING"])
    try:
        assert query["rel"] == [OIC_ISSUER]
        resource = query["resource"][0]
    except KeyError:
        resp = BadRequest("Missing parameter in request")
    else:
        wf = WebFinger()
        resp = Response(wf.response(subject=resource, base=AUTHZSRV.baseurl))
    return resp


def manage(uid, headers=None):
    if headers is None:
        headers = []

    resp = Response(mako_template="manage.mako", template_lookup=azs.LOOKUP,
                    headers=headers)

    res_set = AUTHZSRV.resource_sets_by_user(uid, collapse=True)
    # returns list of ResourceSetDescription instances
    rs_list = [(r["name"], AUTHZSRV.map_id_rsid[r["_id"]]) for r in res_set]

    argv = {
        "action": "action",
        "method": "POST",
        "rs_list": rs_list,
        "req_list": SPS,
        "user": uid
    }
    return resp, argv


ENDPOINT2CB = {
    "dynamic_client": dynamic_client,
    "token": token,
    "user": oidc_authorization_request,
    "resource_set_registration": resource_set_registration,
    "introspection": introspection,
    "permission_registration": permission_registration,
    "rpt": rpt,
    "authorization_request": authorization_request,
    #"authorization": oidc_authorization_request,
    "user_info": user_info,
    "userinfo": user_info,
}


def application(environ, start_response):
    path = environ.get('PATH_INFO', '').lstrip('/')

    session = {}
    try:
        cookie = environ["HTTP_COOKIE"]
        try:
            _tmp = CookieHandler.get_cookie_value(cookie, COOKIE_NAME)
        except InvalidCookieSign:
            _tmp = None
        if _tmp:
            # 3-tuple (val, timestamp, type)
            session = eval(_tmp[0])
        else:
            try:
                (uid, _, typ) = CookieHandler.get_cookie_value(cookie, "pyoidc")
                if typ == "sso":
                    session = {"user": uid}
            except (InvalidCookieSign, TypeError):
                pass
    except KeyError:
        pass

    argv = {}
    resp = None

    logger.info("PATH: %s" % path)
    logger.info("Session: %s" % (session,))

    if path == "robots.txt":
        resp = static(environ, session, "static/robots.txt")
    elif path.startswith("static/"):
        resp = static(environ, session, path)
    elif path == "permission":
        resp, argv = chose_permissions(environ, session)
    elif path == "permreg" or path == "manage/permreg":
        resp, argv = set_permission(environ, session)
    elif path == "verify":
        resp, argv = verify(environ)
    elif path == "authn":
        resp, argv = authn(environ, session)
    elif path.startswith("resset/"):
        uid = path.split("/")[1]
        resp, argv = resource_set(uid)
    elif path.startswith("permits/"):
        uid = path.split("/")[1]
        resp, argv = permits(uid)
    elif path == "action" or path == "manage/action":
        query = parse_qs(get_body(environ))
        logger.debug("%s: %s" % (path, query))
        if query["commit"] == ["add"]:
            _rsid = query["resource"][0]
            try:
                rst = AUTHZSRV.resource_set_tree_by_rsid(_rsid)
            except UnknownObject:
                resp = BadRequest("Unknown object")
            except Exception, err:
                raise
            else:
                resp, argv = edit_permission_form(
                    query["user"][0], rst, query["requestor"][0],
                    AUTHZSRV.resource_set_name(_rsid))
        elif query["commit"] == ["display"]:
            resp, argv = get_permissions(environ, session)
        elif query["commit"] == ["modify"]:
            resp, argv = modify_permission(environ, session)
        elif query["commit"] == ["delete"]:
            resp, argv = delete_permissions(environ, session)

    #elif path.startswith("manage/"):
    #    uid = path.split("/")[1]
    #    resp, argv = manage(uid)
    elif path == "manage":
        if not session or "user" not in session:
            # demand authentication
            resp, argv = authenticate(environ, session, "manage")
        else:
            resp, argv = manage(session["user"])
    else:
        query = parse_qs(environ["QUERY_STRING"])
        prepath = path.split("/")[0]
        if path == ".well-known/openid-configuration":
            resp = openid_provider_configuration(environ, session)
        elif path == ".well-known/uma-configuration":
            resp = uma_provider_configuration(environ, session)
        elif path == ".well-known/webfinger":
            resp = webfinger(environ)
        else:
            resp = None
            for service in AUTHZSRV.services():
                if prepath == service:
                    logger.info("Accessing %s" % service)
                    try:
                        resp, argv = ENDPOINT2CB[prepath](environ, session,
                                                          query)
                        break
                    except Exception, err:
                        raise

    if isinstance(resp, Response):
        pass
    else:
        resp = NotImplemented(path)

    return resp(environ, start_response, **argv)

# -----------------------------------------------------------------------------


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

from saml2.mdstore import MetaDataFile, MetaDataMD

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


def _cmp(item1, item2):
    if item1[0] == item2[0]:
        return 0
    elif item1[0] > item2[0]:
        return 1
    else:
        return -1


def get_sp(item, typ):
    if typ == "local":
        metad = MetaDataFile(ONTS.values(), item, item)
    elif typ == "mdfile":
        metad = MetaDataMD(ONTS.values(), item, item)
    else:
        raise Exception("Don't do that format yet")

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
                if not _name:
                    _name = entid
                sps.append((_name, entid))
    sps.sort(_cmp)
    return sps


if __name__ == '__main__':
    SERVER_CERT = "../pki/server.crt"
    SERVER_KEY = "../pki/server.key"
    CA_BUNDLE = None
    SPS = get_sp("sp/sp.xml", "local")
    SPS.extend(get_sp("/Users/rolandh/code/pysaml2/tests/swamid2.md", "mdfile"))

    # The UMA AS
    AUTHZSRV = azs.main(BASE, CookieHandler)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', PORT), application)

    if BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            SERVER_CERT, SERVER_KEY, CA_BUNDLE)

    #logger.info("RP server starting listening on port:%s" % rp_conf.PORT)
    print "AS started, listening on port:%s" % PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
