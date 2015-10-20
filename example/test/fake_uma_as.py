import json
import socket
from urllib.parse import urlparse, parse_qs
from mako.lookup import TemplateLookup
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.user import UserAuthnMethod, UsernamePasswordMako
from oic.utils.authn.user import BasicAuthn
from oic.utils.authz import Implicit
from oic.utils.keyio import keyjar_init
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo
from uma import authzsrv
from uma.authzsrv import OidcDynRegUmaAS

__author__ = 'roland'

AUTHZ = Implicit("PERMISSION")
CDB = {}
AUTHZSRV = None

PASSWD = {
    "linda": "krall",
    "hans": "thetake",
    "user": "howes",
    "https://sp.example.org/": "code"
}


USERDB = {
    "hans": {
        "name": "Hans Granberg",
        "nickname": "Hasse",
        "email": "hans@example.org",
        "verified": False,
        "sub": "hans.granberg@example.org"
    },
    "linda": {
        "name": "Linda Lindgren",
        "nickname": "Linda",
        "email": "linda@example.com",
        "verified": True,
        "sub": "linda.lindgren@example.com"
    }
}

USERINFO = UserInfo(USERDB)

KEYS = [
    {"type": "RSA", "key": "as.key", "use": ["enc", "sig"]},
]


class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, uid="Linda"):
        UserAuthnMethod.__init__(self, srv)
        self.user = uid

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}


class BasicAuthnExtra(BasicAuthn):
    def __init__(self, srv, symkey):
        BasicAuthn.__init__(self, srv, None, 0)
        self.symkey = symkey

    def verify_password(self, user, password):
        assert password == "hemligt"


ROOT = './'
LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')


class Response():
    def __init__(self, base=None):
        self.status_code = 200
        if base:
            for key, val in base.items():
                self.__setitem__(key, val)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, item):
        return getattr(self, item)


ENDPOINT = {
    "authorization_endpoint": "/authorization",
    "token_endpoint": "/token",
    "user_info_endpoint": "/userinfo",
    "check_session_endpoint": "/check_session",
    "refresh_session_endpoint": "/refresh_session",
    "end_session_endpoint": "/end_session",
    "registration_endpoint": "/registration",
    "discovery_endpoint": "/discovery",
    "register_endpoint": "/register",
    "dynamic_client_endpoint": '/dynreg'
}


class FakeUmaAs(OidcDynRegUmaAS):
    def http_request(self, path, method, **kwargs):
        part = urlparse(path)
        path = part[2]
        query = part[4]
        self.host = "%s://%s" % (part.scheme, part.netloc)

        response = Response
        response.status_code = 500
        response.text = ""

        if path == ENDPOINT["authorization_endpoint"]:
            assert method == "GET"
            response = self.authorization_endpoint(query)
        elif path == ENDPOINT["token_endpoint"]:
            assert method == "POST"
            response = self.token_endpoint(kwargs["data"])
        elif path == ENDPOINT["dynamic_client_endpoint"]:
            if method == "POST":
                response = self.oauth_registration_endpoint(kwargs["data"])
        elif path == ENDPOINT["registration_endpoint"]:
            if method == "POST":
                response = self.oidc_registration_endpoint(kwargs["data"])
        elif path == "/.well-known/webfinger":
            assert method == "GET"
            qdict = parse_qs(query)
            response.status_code = 200
            response.text = self.srv["oidc"].webfinger.response(
                qdict["resource"][0], "%s/" % self.hostname)
        elif path == "/.well-known/openid-configuration":
            assert method == "GET"
            response = self.srv["oidc"].openid_conf()

        return response


# init the AS

def main(base, cookie_handler):
    as_conf = {
        "version": "1.0",
        "issuer": base,
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

    base_url = "http://%s" % socket.gethostname()
    ab = AuthnBroker()
    ab.add("linda", DummyAuthn(None, "linda"))
    ab.add("hans", DummyAuthn(None, "hans"))

    AUTHZSRV = FakeUmaAs(
        base, SessionDB(base_url), CDB, ab, USERINFO, AUTHZ,
        verify_client, "1234567890", keyjar=None, configuration=as_conf,
        base_url=base)

    cookie_handler.init_srv(AUTHZSRV)
    jwks = keyjar_init(AUTHZSRV, KEYS, "a%d")

    fp = open("static/jwk_as.json", "w")
    fp.write(json.dumps(jwks))
    fp.close()

    return AUTHZSRV





