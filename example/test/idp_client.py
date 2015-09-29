#!/usr/bin/env python
import logging
from beaker.middleware import SessionMiddleware
from beaker.session import Session
from cherrypy import wsgiserver
from uma.userinfo import UMAUserInfo

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


PORT = 8090
BASE = "http://localhost:%s" % PORT
IDP_CLIENT = None

EPPN2UID = {"linda.lindgren@example.com": "linda"}

# ........................................................................


def application(environ, start_response):
    global IDP_CLIENT
    session = Session(environ['beaker.session'])
    path = environ.get('PATH_INFO', '').lstrip('/')

    if path.startswith("info"):
        # Assume query of the form
        # info/<uid>/<bundle>[?attr=<attribute>[&attr=<attribute>]] or
        # info/<uid>[?attr=<attribute>[&attr=<attribute>]]
        owner = path[5:]
        #owner = owner.replace("--", "@")
        resp = IDP_CLIENT.get_info(owner)
    elif path.startswith("authz_cb"):  # Authorization redirect URI
        try:
            owner = IDP_CLIENT.get_tokens(environ["QUERY_STRING"])
            resp = IDP_CLIENT.get_info(owner)
        except Exception as err:
            raise
    else:
        resp = None

    if resp:
        pass
    else:
        resp = NotImplemented(path)

    return resp(environ, start_response)

# -----------------------------------------------------------------------------

if __name__ == '__main__':
    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    IDP_CLIENT = UMAUserInfo(BASE, ["%s/authz_cb" % BASE],
                             "https://localhost:8089", acr="BasicAuthn")

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    #if BASE.startswith("https"):
    #    from cherrypy.wsgiserver import ssl_pyopenssl
    #
    #    SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
    #        SERVER_CERT, SERVER_KEY, CA_BUNDLE)

    #logger.info("RP server starting listening on port:%s" % rp_conf.PORT)
    print("Client started, listening on port:%s" % PORT)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
