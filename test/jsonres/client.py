import logging
import urllib
from urlparse import parse_qs
from cherrypy import wsgiserver
from mako.lookup import TemplateLookup
from oic.oauth2 import rndstr
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.http_util import Response
from oic.utils.http_util import NotFound
from uma.client import UMAClient

__author__ = 'roland'

logger = logging.getLogger("")
LOGFILE_NAME = 'rs.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")
hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


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


def manage(headers=None):
    if headers is None:
        headers = []
    resp = Response(mako_template="resource.mako", template_lookup=LOOKUP,
                    headers=headers)
    argv = {}
    return resp, argv

# ======================================================================


def get_resource(url, who):
    resp = CLIENT(url, who, "GET")
    return resp


def modify_resource(url, who):
    # Try to read the resource
    resp = get_resource(url, who)
    # if that went OK, display modify screen

    return resp


def delete_resource(url, who):
    resp = CLIENT(url, who, "DELETE")
    return resp


def add_resource(url, who):
    # ask for input
    body = {"foo": "bar"}

    resp = CLIENT(url, who, body=body)
    return resp

# ======================================================================


def create_query(srv, uid, rid, **kwargs):
    url = "%s/info/%s/%s" % (srv, uid, rid)
    if kwargs:
        url += "&%s" % urllib.urlencode(**kwargs)

    return url


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

    argv = {}

    if path in ["", "manage"]:
        resp, argv = manage()
    elif path == "action":
        try:
            whoami = session["whoami"]
        except KeyError:
            whoami = rndstr()
            session["whoami"] = whoami

        # The form is POSTed
        query = parse_qs(get_body(environ))

        url = create_query(query["host"][0], query["owner"][0],
                           query["name"][0])

        logger.debug("%s: %s" % (url, query))

        if query["commit"] == ["add"]:
            resp, argv = add_resource(url, whoami)
        elif query["commit"] == ["display"]:
            resp, argv = get_resource(url, whoami)
        elif query["commit"] == ["modify"]:
            resp, argv = modify_resource(url, whoami)
        elif query["commit"] == ["delete"]:
            resp, argv = delete_resource(url, whoami)

    if not resp:
        logger.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")

    return resp(environ, start_response, **argv)

# ======================================================================
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

RES_SRV = "https://localhost:8089"
VERIFY_SSL = True

PORT = 8092
BASE = "http://localhost:%s" % PORT

if __name__ == "__main__":
    from beaker.middleware import SessionMiddleware

    SERVER_CERT = "../pki/server.crt"
    SERVER_KEY = "../pki/server.key"
    CA_BUNDLE = None

    reginfo = {
        "client_name": BASE,
        "application_type": "native",
        "redirect_uris": ["%s/authz_cb" % BASE]
    }

    AUTHN = UsernamePasswordMako(None, "login_rs.mako", LOOKUP, PASSWD)

    CLIENT = UMAClient(BASE, ["%s/authz_cb" % BASE], verify_ssl=VERIFY_SSL)

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    SRV = wsgiserver.CherryPyWSGIServer(
        ('0.0.0.0', PORT), SessionMiddleware(application, session_opts))

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
