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


# ........................................................................


#class IdPUmaClient(object):
#
#    def __init__(self, client_name, redirect_uris, resource_srv):
#        # The UMA Client
#        reginfo = {
#            "client_name": client_name,
#            "application_type": "native",
#            "redirect_uris": redirect_uris
#        }
#
#        cconf = {"client_authn_method": CLIENT_AUTHN_METHOD}
#        self.client = Client({}, cconf, registration_info=reginfo)
#        self.client.redirect_uris = redirect_uris
#        self.resource_srv = resource_srv
#
#    def _query(self, sp_user, user, attr=None):
#        try:
#            rpt = self.client.token[sp_user]["RPT"]
#        except KeyError:
#            rpt = None
#
#        url = create_query(self.resource_srv, user.replace("@", "--"), attr)
#
#        if rpt:
#            kwargs = {"headers": [("Authorization", "Bearer %s" % rpt)]}
#        else:
#            kwargs = {}
#
#        return self.client.send(url, "GET", **kwargs)
#
#    def get_info(self, user, attr=None):
#        """
#
#        :param user: user = <uid>--<domain>--<sp_entityid>
#        :param attr: A list of wanted attributes
#        """
#        sp_user = user.replace("--", "@")
#        uad = sp_user.rsplit("@",1)[0]
#        resp = self._query(sp_user, uad, attr)
#
#        if resp.status_code == 200:
#            return Response(resp.text)
#
#        if resp.status_code == 401:  # No RPT
#            as_uri = resp.headers["as_uri"]
#            resp = self.client.acquire_grant(as_uri, "RPT", sp_user)
#            if resp.status_code == 302:  # which it should be
#                headers = [(a, b) for a, b in resp.headers.items()
#                           if a != "location"]
#                return Redirect(resp.headers["location"], headers=headers)
#            elif resp.status_code == 200:  # ???
#                return Response(resp.text)
#            else:
#                return R2C[resp.status_code](resp.text)
#
#        if resp.status_code == 403:  # Permission registered, got ticket
#            prr = PermissionRegistrationResponse().from_json(resp.text)
#            resp = self.client.authorization_data_request(sp_user,
#                                                          prr["ticket"])
#            if resp.status_code == 200:
#                return self.get_info(user, attr)
#
#        raise UMAError()
#
#    def get_tokens(self, query):
#        aresp = AuthorizationResponse().from_urlencoded(query)
#        uid = self.client.acquire_access_token(aresp, "AAT")
#        self.client.get_rpt(uid)
#        return uid


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
        except Exception, err:
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
                             "http://localhost:8089")

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
