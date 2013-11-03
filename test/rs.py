import base64
import copy
import hashlib
import re
import sys
import logging
import traceback
import urllib

from urlparse import parse_qs
from cherrypy import wsgiserver

from beaker.middleware import SessionMiddleware
from beaker.session import Session
from mako.lookup import TemplateLookup
from oic.oauth2.message import AuthorizationResponse, MissingRequiredAttribute
from oic.oauth2.message import MissingRequiredValue
from uma.saml2uma import ErrorResponse
from uma.saml2uma import ResourceResponse

from oic.utils.http_util import Response, Forbidden
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import NotFound
from oic.utils.http_util import ServiceError
from oic.utils.userinfo import UserInfo
import requests
from uma import init_keyjar
from uma.message import ResourceSetDescription, PermissionRegistrationResponse

from uma.resourcesrv import ResourceServer
from uma.resourcesrv import DESC_BASE
from uma.client import UMA_SCOPE

__author__ = 'rolandh'

logger = logging.getLogger(__name__)

PORT = 8089
HOST = "http://localhost:%s" % PORT
CONFIG = {
    "scope": [UMA_SCOPE["PAT"], "openid"],
    "base_url": HOST,
    "registration_info": {
        "client_name": HOST,
        "application_type": "web",
        "redirect_uris": ["%s/uma" % HOST]
    },
    "template_lookup": TemplateLookup(directories=['templates', 'htdocs'],
                                      module_directory='modules',
                                      input_encoding='utf-8',
                                      output_encoding='utf-8'),
}
KEYS = {
    "RSA": {
        "key": "as.key",
        "usage": ["enc", "sig"]
    }
}

RES_SRV = None
RP = None


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

        return Response(text, headers=[('Content-Type', ctype)])
    except IOError:
        return NotFound()

# ........................................................................


#noinspection PyUnusedLocal
def dataset_endpoint(environ, session, path, query):
    owner = path[5:]
    return RES_SRV.dataset_endpoint(query, owner, environ)

# Dataset url syntax
# /info/<userid>?attribute=<SP separated list>&bundle=<SP separated list>

URLS = [
    (r'^info', dataset_endpoint),
]

USERDB = {
    "hans.granberg@example.com": {
        "displayName": "Hans Granberg",
        "givenName": "Hans",
        "sn": "Granberg",
        "eduPersonNickname": "Hasse",
        "email": "hans@example.org",
    },
    "linda.lindgren@example.com": {
        "displayName": "Linda Lindgren",
        "eduPersonNickname": "Linda",
        "givenName": "Linda",
        "sn": "Lindgren",
        "email": "linda@example.com",
    }
}

BUNDLES = {
    "name": ["givenName", "displayName", "sn", "initials", "eduPersonNickname"],
    "static_org_info": ["c", "o", "co"],
    "other": ["eduPersonPrincipalName", "eduPersonScopedAffiliation", "mail"],
    "address": ["l", "streetAddress", "stateOrProvinceName",
                "postOfficeBox", "postalCode", "postalAddress",
                "co"]
}


# Will produce something like this
#{
#  "resource_set_id": "<uid>",
#  "scopes": [
#      "http://idm.example.com/dev/actions/view",
#      "http://idm.example.com/dev/actions/all"
#  ],
#  "member": [
#       {
#           "resource_set_id":"<uid>:address",
#           "member": [
#                {"resource_set_id": "<uid>:street_address"}
#                {"resource_set_id": "<uid>:locality"}
#                {"resource_set_id": "<uid>:postal_code"}
#                {"resource_set_id": "<uid>:country"}
#           ]
#       }
#  ]
#}
def build_description_bundles(uid, info):
    """
    :param uid: The entity identifier
    :param info: A dictionary with information about the entity
    :return: A resource set description
    """
    singles = info.keys()
    desc = ResourceSetDescription(
        name=uid, scope=["http://its.umu.se/uma/actions/read"])
    for name, collection in BUNDLES.items():
        bundle = None
        for attr in collection:
            if attr in info:
                try:
                    singles.remove(attr)
                except AttributeError:
                    pass
                res = ResourceSetDescription(
                    name="%s:%s" % (uid, attr),
                    scope=["http://its.umu.se/uma/actions/read"])
                if not bundle:
                    bundle = ResourceSetDescription(
                        name="%s:%s" % (uid, name),
                        scope=["http://its.umu.se/uma/actions/read"])
                    try:
                        desc["member"].append(bundle)
                    except KeyError:
                        desc["member"] = bundle
                try:
                    bundle["member"].append(res)
                except KeyError:
                    bundle["member"] = res
    return desc


def build_description(uid, info):
    """
    :param uid: The entity identifier
    :param info: A dictionary with information about the entity
    :return: A resource set description
    """
    scopes = [DESC_BASE]  # ALL
    for attr, val in info.items():
        scopes.append("%s/%s" % (DESC_BASE, attr))
        if isinstance(val, basestring):
            scopes.append("%s/%s/%s" % (DESC_BASE, attr, urllib.quote(val)))
        else:
            for v in val:
                scopes.append("%s/%s/%s" % (DESC_BASE, attr, urllib.quote(v)))

    desc = ResourceSetDescription(name=uid, scopes=scopes)
    return desc


RESOURCE_PATTERN = "info/%s"


def application(environ, start_response):
    session = Session(environ['beaker.session'])

    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, session, "static/robots.txt")
    elif path.startswith("static/"):
        return static(environ, session, path)

    try:
        query = parse_qs(environ["QUERY_STRING"])
    except KeyError:
        query = None

    if path == "rp":
        link = ""
        if "uid" in query:
            try:
                link = RES_SRV.find_srv_discovery_url(resource=query["uid"][0])
            except requests.ConnectionError:
                resp = ServiceError("Webfinger lookup failed, connection error")
                return resp(environ, start_response)
        elif "url" in query:
            link = query["url"][0]

        if link:
            RES_SRV.srv_discovery_url = link
            md5 = hashlib.md5()
            md5.update(link)
            opkey = base64.b16encode(md5.digest())
            session["callback"] = True
            func = getattr(RES_SRV, "begin")
            return func(environ, start_response, session, opkey)
        else:
            resp = BadRequest()
            return resp(environ, start_response)
    elif path.startswith("info"):
        # Assume query of the form
        # info/<uid>/<bundle>[?attr=<attribute>[&attr=<attribute>]] or
        # info/<uid>[?attr=<attribute>[&attr=<attribute>]]
        owner = path[5:]
        owner = owner.replace("--", "@")
        res = RES_SRV.dataset_endpoint(query, owner, environ)
        # either a ErrorResponse or a ResourceResponse

        er = ErrorResponse().from_json(res)
        try:
            er.verify()
            headers = []
            for var in ["as_uri", "host_id", "error"]:
                try:
                    headers.append((var, str(er[var])))
                except KeyError:
                    pass

            if "ticket" in er:
                prr = PermissionRegistrationResponse(ticket=er["ticket"])
                resp = Forbidden(prr.to_json(), headers=headers,
                                 content="application/json")
            else:
                resp = Unauthorized(headers=headers)
        except MissingRequiredAttribute:
            rr = ResourceResponse().from_json(res)
            resp = Response(rr.to_json())

        return resp(environ, start_response)

    resp = None
    if path in RES_SRV.oic_client:
        # back after the authorization at the AS
        # Should provide an authorization code which means I can get the access
        # token
        aresp = AuthorizationResponse().from_urlencoded(environ["QUERY_STRING"])
        _cli = RES_SRV.oic_client[path]
        uid = _cli.acquire_access_token(aresp, "PAT")

        # The RS registering Alice resources
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
        desc = build_description(uid, RES_SRV.dataset(uid))

        try:
            RES_SRV.register_resource_set_description(uid, desc.to_json(), uid)
        except Exception, err:
            raise

        resp = Response("OK")

    if not resp:
        for regex, callback in URLS:
            match = re.search(regex, path)
            if match is not None:
                logger.info("callback: %s" % callback)
                try:
                    resp = callback(environ, session, path, query)
                except Exception, err:
                    print >> sys.stderr, "%s" % err
                    message = traceback.format_exception(*sys.exc_info())
                    print >> sys.stderr, message
                    logger.exception("%s" % err)
                    resp = ServiceError("%s" % err)
                    return resp(environ, start_response)

    if not resp:
        logger.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")

    return resp(environ, start_response)

# -----------------------------------------------------------------------------


class IdmUserInfo(UserInfo):
    """ Read only interface to a user info store """

    @staticmethod
    def _filtering(userinfo, authzdesc=None):
        """
        Return only those claims that are asked for.
        It's a best effort task; if essential claims are not present
        no error is flagged.

        :param userinfo: A dictionary containing the available user info.
        :param authzdesc: A list of Authz descriptions
        :return: A dictionary of attribute values
        """

        if authzdesc is None:
            return copy.copy(userinfo)
        else:
            ld = len(DESC_BASE)
            rel_scopes = []
            for ad in authzdesc:
                rel_scopes.extend([s[ld:] for s in ad["scopes"]])

            if "" in rel_scopes:  # Anything match
                return copy.copy(userinfo)
            else:
                result = {}
                for attr, val in userinfo.items():
                    if attr in rel_scopes:
                        result[attr] = val
                    else:
                        _val = []
                        if isinstance(val, basestring):
                            ava = "%s/%s" % (attr, urllib.quote(val))
                            if ava in rel_scopes:
                                _val.append(val)
                        else:
                            for v in val:
                                ava = "%s/%s" % (attr, urllib.quote(v))
                                if ava in rel_scopes:
                                    _val.append(v)
                        if _val:
                            result[attr] = _val

            return result

    def __call__(self, userid, authzdesc=None, **kwargs):
        try:
            return self._filtering(self.db[userid], authzdesc)
        except KeyError:
            return {}

if __name__ == '__main__':
    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    #parser = argparse.ArgumentParser()
    #parser.add_argument(dest="config")
    #args = parser.parse_args()
    #
    #sys.path.insert(0, ".")

    # The UMA RS
    RES_SRV = ResourceServer(IdmUserInfo(USERDB), CONFIG, baseurl=HOST)
    init_keyjar(RES_SRV, KEYS, "static/jwk_rs.json")

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    #if BASE.startswith("https"):
    #    from cherrypy.wsgiserver import ssl_pyopenssl
    #
    #    SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
    #        SERVER_CERT, SERVER_KEY, CA_BUNDLE)

    #logger.info("RP server starting listening on port:%s" % rp_conf.PORT)
    print "RS started, listening on port:%s" % PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
