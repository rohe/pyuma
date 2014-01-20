import socket
from mako.lookup import TemplateLookup
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client, BearerHeader
from oic.utils.authn.client import ClientSecretPost
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.user import UserAuthnMethod, UsernamePasswordMako
from oic.utils.authn.user import BasicAuthn
from oic.utils.authz import Implicit
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo
from uma import authzsrv
from uma.keyjar import init_keyjar

__author__ = 'roland'

AUTHZ = Implicit("PERMISSION")
CDB = {}

PASSWD = {
    "alice": "krall",
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
    "alice": {
        "name": "Alice",
        "nickname": "linda",
        "email": "alice@example.com",
        "verified": True,
        "sub": "alice@example.com"
    }
}

USERINFO = UserInfo(USERDB)

KEYS = {
    "RSA": {
        "key": "as.key",
        "usage": ["enc", "sig"]
    }
}


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

    ab = AuthnBroker()
    ab.add("alice", DummyAuthn(None, "alice"))
    #AB.add("hans", DummyAuthn(None, "hans.granberg@example.org"))
    ab.add("UserPwd",
           UsernamePasswordMako(None, "login2.mako", LOOKUP, PASSWD,
                                "%s/authorization" % base),
           10, "http://%s" % socket.gethostname())
    ab.add("BasicAuthn", BasicAuthnExtra(None, PASSWD), 10,
           "http://%s" % socket.gethostname())

    AUTHZSRV = authzsrv.OAuth2UmaAS(base, SessionDB(), CDB, ab, AUTHZ,
                                    verify_client, "1234567890123456",
                                    keyjar=None,
                                    configuration=as_conf,
                                    base_url=base,
                                    client_info_url="%s/" % base,
                                    client_authn_methods={
                                        "client_secret_post": ClientSecretPost,
                                        "client_secret_basic": ClientSecretBasic,
                                        "bearer_header": BearerHeader})

    cookie_handler.init_srv(AUTHZSRV)
    init_keyjar(AUTHZSRV, KEYS, "static/jwk_as.json")

    return AUTHZSRV