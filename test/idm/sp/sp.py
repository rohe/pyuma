#!/usr/bin/env python
import ConfigParser
import json
import logging
import socket
import urllib
import xmldsig
import xmlenc
import re
import argparse

from mako.lookup import TemplateLookup
from urlparse import parse_qs
from Cookie import SimpleCookie

from saml2 import BINDING_HTTP_REDIRECT, samlp, saml
from saml2 import BINDING_SOAP
from saml2 import time_util
from saml2 import ecp
from saml2 import BINDING_HTTP_ARTIFACT
from saml2 import BINDING_HTTP_POST
from saml2.assertion import Policy
from saml2.client import Saml2Client
from saml2.ecp_client import PAOS_HEADER_INFO
from saml2.httputil import geturl, make_cookie
from saml2.httputil import get_post
from saml2.httputil import Response
from saml2.httputil import BadRequest
from saml2.httputil import ServiceError
from saml2.httputil import SeeOther
from saml2.httputil import Unauthorized
from saml2.httputil import NotFound
from saml2.httputil import Redirect
from saml2.httputil import NotImplemented
from saml2.mdie import to_dict
from saml2.response import StatusError
from saml2.response import VerificationError
from saml2.s_utils import UnknownPrincipal
from saml2.s_utils import UnsupportedBinding
from saml2.s_utils import sid
from saml2.s_utils import rndstr

logger = logging.getLogger("")
hdlr = logging.FileHandler('sp.log')
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
logger.addHandler(hdlr)
logger.setLevel(logging.DEBUG)


ONTS = {
    saml.NAMESPACE: saml,
    samlp.NAMESPACE: samlp,
    xmldsig.NAMESPACE: xmldsig,
    xmlenc.NAMESPACE: xmlenc
}

SP = None
SEED = ""
POLICY = None


class SessionDB(object):
    def __init__(self, maxsize=10):
        self.db = {}
        self.order = []
        self.maxsize = maxsize

    def __setitem__(self, key, value):
        if len(self.db) > self.maxsize:
            old = self.order.pop()  # returns the key to the oldest item
            del self.db[old]
        self.order.insert(0, key)
        self.db[key] = value

    def __getitem__(self, item):
        return self.db[item]


def ip_addresses():
    return [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
            if not ip.startswith("127.")]


SESSIONDB = SessionDB()

LOOKUP = TemplateLookup(
    directories=['templates', 'htdocs'],
    module_directory='modules',
    input_encoding='utf-8',
    output_encoding='utf-8')


def handleStatic(environ, start_response, path):
    """
    Creates a response for a static file.
    :param environ: wsgi enviroment
    :param start_response: wsgi start response
    :param path: the static file and path to the file.
    :return: wsgi response for the static file.
    """
    try:
        text = open(path).read()
        if path.endswith(".ico"):
            resp = Response(text, headers=[('Content-Type', "image/x-icon")])
        elif path.endswith(".html"):
            resp = Response(text, headers=[('Content-Type', 'text/html')])
        elif path.endswith(".txt"):
            resp = Response(text, headers=[('Content-Type', 'text/plain')])
        elif path.endswith(".css"):
            resp = Response(text, headers=[('Content-Type', 'text/css')])
        elif path.endswith(".js"):
            resp = Response(text, headers=[('Content-Type', 'text/javascript')])
        elif path.endswith(".png"):
            resp = Response(text, headers=[('Content-Type', 'image/png')])
        else:
            resp = Response(text)
    except IOError:
        resp = NotFound()
    return resp(environ, start_response)


class ECP_response(object):
    code = 200
    title = 'OK'

    def __init__(self, content):
        self.content = content

    #noinspection PyUnusedLocal
    def __call__(self, environ, start_response):
        start_response('%s %s' % (self.code, self.title),
                       [('Content-Type', "text/xml")])
        return [self.content]


def _expiration(timeout, tformat=None):
    # Wed, 06-Jun-2012 01:34:34 GMT
    if not tformat:
        tformat = '%a, %d-%b-%Y %T GMT'

    if timeout == "now":
        return time_util.instant(tformat)
    else:
        # validity time should match lifetime of assertions
        return time_util.in_a_while(minutes=timeout, format=tformat)

IGNORE_KEYS = [
    "__class__",
    "{http://www.w3.org/2001/XMLSchema-instance}nil",
    "{http://www.w3.org/2001/XMLSchema-instance}type"
]


def simplify(item):
    if isinstance(item, basestring):
        res = item
    elif isinstance(item, list):
        res = []
        for it in item:
            _val = simplify(it)
            if _val:
                res.append(_val)
    elif isinstance(item, dict):
        res = {}
        for key, val in item.items():
            if key in IGNORE_KEYS :
                continue
            _val = simplify(val)
            if _val:
                res[key] = _val
    return res


class Cache(object):
    def __init__(self):
        self.uid2user = {}
        self.cookie_name = "spauthn"
        self.outstanding_queries = {}
        self.relay_state = {}
        self.user = {}
        self.result = {}

    def kaka2user(self, kaka):
        logger.debug("KAKA: %s" % kaka)
        if kaka:
            cookie_obj = SimpleCookie(kaka)
            morsel = cookie_obj.get(self.cookie_name, None)
            if morsel:
                try:
                    return self.uid2user[morsel.value]
                except KeyError:
                    return None
            else:
                logger.debug("No spauthn cookie")
        return None

    def delete_cookie(self, environ=None, kaka=None):
        if not kaka:
            kaka = environ.get("HTTP_COOKIE", '')
        logger.debug("delete KAKA: %s" % kaka)
        if kaka:
            _name = self.cookie_name
            cookie_obj = SimpleCookie(kaka)
            morsel = cookie_obj.get(_name, None)
            cookie = SimpleCookie()
            cookie[_name] = ""
            cookie[_name]['path'] = "/"
            logger.debug("Expire: %s" % morsel)
            cookie[_name]["expires"] = _expiration("dawn")
            return tuple(cookie.output().split(": ", 1))
        return None

    def user2kaka(self, user):
        uid = rndstr(32)
        self.uid2user[uid] = user
        cookie = SimpleCookie()
        cookie[self.cookie_name] = uid
        cookie[self.cookie_name]['path'] = "/"
        cookie[self.cookie_name]["expires"] = _expiration(480)
        logger.debug("Cookie expires: %s" % cookie[self.cookie_name]["expires"])
        return tuple(cookie.output().split(": ", 1))


# -----------------------------------------------------------------------------
# RECEIVERS
# -----------------------------------------------------------------------------


class Service(object):
    def __init__(self, environ, start_response, user=None):
        self.environ = environ
        logger.debug("ENVIRON: %s" % environ)
        self.start_response = start_response
        self.user = user
        self.sp = None
        
    def unpack_redirect(self):
        if "QUERY_STRING" in self.environ:
            _qs = self.environ["QUERY_STRING"]
            return dict([(k, v[0]) for k, v in parse_qs(_qs).items()])
        else:
            return None

    def unpack_post(self):
        _dict = parse_qs(get_post(self.environ))
        logger.debug("unpack_post:: %s" % _dict)
        try:
            return dict([(k, v[0]) for k, v in _dict.items()])
        except Exception:
            return None

    def unpack_soap(self):
        try:
            query = get_post(self.environ)
            return {"SAMLResponse": query, "RelayState": ""}
        except Exception:
            return None

    def unpack_either(self):
        if self.environ["REQUEST_METHOD"] == "GET":
            _dict = self.unpack_redirect()
        elif self.environ["REQUEST_METHOD"] == "POST":
            _dict = self.unpack_post()
        else:
            _dict = None
        logger.debug("_dict: %s" % _dict)
        return _dict

    def operation(self, _dict, binding):
        logger.debug("_operation: %s" % _dict)
        if not _dict:
            resp = BadRequest('Error parsing request or no request')
            return resp(self.environ, self.start_response)
        else:
            if "SAMLResponse" in _dict:
                return self.do(_dict["SAMLResponse"], binding,
                               _dict["RelayState"], mtype="response")
            elif "SAMLRequest" in _dict:
                return self.do(_dict["SAMLRequest"], binding,
                               _dict["RelayState"], mtype="request")

    def artifact_operation(self, _dict):
        if not _dict:
            resp = BadRequest("Missing query")
            return resp(self.environ, self.start_response)
        else:
            # exchange artifact for response
            request = self.sp.artifact2message(_dict["SAMLart"], "spsso")
            return self.do(request, BINDING_HTTP_ARTIFACT, _dict["RelayState"])

    def response(self, binding, http_args):
        if binding == BINDING_HTTP_ARTIFACT:
            resp = Redirect()
        else:
            resp = Response(http_args["data"], headers=http_args["headers"])
        return resp(self.environ, self.start_response)

    def do(self, query, binding, relay_state="", mtype="response"):
        pass

    def redirect(self):
        """ Expects a HTTP-redirect response """

        _dict = self.unpack_redirect()
        return self.operation(_dict, BINDING_HTTP_REDIRECT)

    def post(self):
        """ Expects a HTTP-POST response """

        _dict = self.unpack_post()
        return self.operation(_dict, BINDING_HTTP_POST)

    def artifact(self):
        # Can be either by HTTP_Redirect or HTTP_POST
        _dict = self.unpack_either()
        return self.artifact_operation(_dict)

    def soap(self):
        """
        Single log out using HTTP_SOAP binding
        """
        logger.debug("- SOAP -")
        _dict = self.unpack_soap()
        logger.debug("_dict: %s" % _dict)
        return self.operation(_dict, BINDING_SOAP)

    def uri(self):
        _dict = self.unpack_either()
        return self.operation(_dict, BINDING_SOAP)

    def not_authn(self):
        resp = Unauthorized('Unknown user')
        return resp(self.environ, self.start_response)


# -----------------------------------------------------------------------------
#  Attribute Consuming service
# -----------------------------------------------------------------------------


class ACS(Service):
    def __init__(self, sp, environ, start_response, cache=None, **kwargs):
        Service.__init__(self, environ, start_response)
        self.sp = sp
        self.outstanding_queries = cache.outstanding_queries
        self.cache = cache
        self.response = None
        self.kwargs = kwargs

    def do(self, response, binding, relay_state="", mtype="response"):
        """
        :param response: The SAML response, transport encoded
        :param binding: Which binding the query came in over
        """
        #tmp_outstanding_queries = dict(self.outstanding_queries)

        if not response:
            logger.info("Missing Response")
            resp = Unauthorized('Unknown user')
            return resp(self.environ, self.start_response)

        try:
            self.response = self.sp.parse_authn_request_response(
                response, binding, self.outstanding_queries)
        except UnknownPrincipal, excp:
            logger.error("UnknownPrincipal: %s" % (excp,))
            resp = ServiceError("UnknownPrincipal: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except UnsupportedBinding, excp:
            logger.error("UnsupportedBinding: %s" % (excp,))
            resp = ServiceError("UnsupportedBinding: %s" % (excp,))
            return resp(self.environ, self.start_response)
        except VerificationError, err:
            resp = ServiceError("Verification error: %s" % (err,))
            return resp(self.environ, self.start_response)
        except Exception, err:
            resp = ServiceError("Other error: %s" % (err,))
            return resp(self.environ, self.start_response)

        logger.info("parsed OK")
        _resp = self.response.response

        logger.debug("%s" % _resp)

        session_id = rndstr(16)
        _info = [
            ("Client Address", ip_addresses()),
            ("Identity Provider", _resp.issuer.text),
            ("SSO Protocol", samlp.NAMESPACE),
        ]

        assertion = simplify(to_dict(_resp, ONTS.values()))
        SESSIONDB[session_id] = {"info": _info, "assertion": assertion}

        resp = Response(mako_template="result.mako",
                        template_lookup=LOOKUP,
                        headers=[])
        uinfo = []
        for key, val in self.response.ava.items():
            if len(val) == 1:
                uinfo.append((key, val[0]))
            elif len(val) > 1:
                uinfo.append((key, ", ".join([v for v in val])))

        uinfo.sort()
        argv = {"uinfo": uinfo, "idp": _resp.issuer.text,
                "session": "/Session/%s" % session_id}
        return resp(self.environ, self.start_response, **argv)

    def verify_attributes(self, ava):
        rest = POLICY.get_entity_categories_restriction(
            self.sp.config.entityid, self.sp.metadata)

        #rest["myKey1"] = None

        #ava["myKey2"] ="whatever"

        akeys = [k.lower() for k in ava.keys()]


        res = {}
        res["less"] = []
        res["more"] = []
        for key, attr in rest.items():
            if key not in ava:
                if key not in akeys:
                    res["less"].append(key)

        for key, attr in ava.items():
            _key = key.lower()
            if _key not in rest:
                res["more"].append(key)
        if res == "":
            res = "="

        return res

# -----------------------------------------------------------------------------
# REQUESTERS
# -----------------------------------------------------------------------------


class SSO(object):
    def __init__(self, sp, environ, start_response, cache=None,
                 wayf=None, discosrv=None, bindings=None):
        self.sp = sp
        self.environ = environ
        self.start_response = start_response
        self.cache = cache
        self.idp_query_param = "IdpQuery"
        self.wayf = wayf
        self.discosrv = discosrv
        if bindings:
            self.bindings = bindings
        else:
            self.bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST,
                             BINDING_HTTP_ARTIFACT]
        logger.info("--- SSO ---")

    def response(self, binding, http_args, dont_send=False):
        if binding == BINDING_HTTP_ARTIFACT:
            resp = Redirect()
        elif binding == BINDING_HTTP_REDIRECT:
            for param, value in http_args["headers"]:
                if param == "Location":
                    resp = SeeOther(value)
                    break
            else:
                resp = ServiceError("Parameter error")
        else:
            resp = Response(http_args["data"], headers=http_args["headers"])

        if dont_send:
            return resp
        else:
            return resp(self.environ, self.start_response)

    def _wayf_redirect(self, came_from):
        sid_ = sid()
        self.cache.outstanding_queries[sid_] = came_from
        logger.info("Redirect to WAYF function: %s" % self.wayf)
        return -1, SeeOther(headers=[('Location', "%s?%s" % (self.wayf, sid_))])

    def _pick_idp(self, came_from):
        """
        If more than one idp and if none is selected, I have to do wayf or
        disco
        """

        _cli = self.sp

        logger.info("[_pick_idp] %s" % self.environ)
        if "HTTP_PAOS" in self.environ:
            if self.environ["HTTP_PAOS"] == PAOS_HEADER_INFO:
                if 'application/vnd.paos+xml' in self.environ["HTTP_ACCEPT"]:
                    # Where should I redirect the user to
                    # entityid -> the IdP to use
                    # relay_state -> when back from authentication

                    logger.info("- ECP client detected -")

                    _rstate = rndstr()
                    self.cache.relay_state[_rstate] = geturl(self.environ)
                    _entityid = _cli.config.ecp_endpoint(
                        self.environ["REMOTE_ADDR"])

                    if not _entityid:
                        return -1, ServiceError("No IdP to talk to")
                    logger.info("IdP to talk to: %s" % _entityid)
                    return ecp.ecp_auth_request(_cli, _entityid, _rstate)
                else:
                    return -1, ServiceError('Faulty Accept header')
            else:
                return -1, ServiceError('unknown ECP version')

        # Find all IdPs
        idps = self.sp.metadata.with_descriptor("idpsso")

        idp_entity_id = None

        # Any specific IdP specified in a query part
        query = self.environ.get("QUERY_STRING")
        if query:
            try:
                _idp_entity_id = dict(parse_qs(query))[
                    self.idp_query_param][0]
                if _idp_entity_id in idps:
                    idp_entity_id = _idp_entity_id
            except KeyError:
                logger.debug("No IdP entity ID in query: %s" % query)
                pass

        if idp_entity_id is None:
            if len(idps) == 1:
                # idps is a dictionary
                idp_entity_id = idps.keys()[0]
            elif not len(idps):
                return -1, ServiceError('Misconfiguration')
            else:
                logger.info("ENVIRON: %s" % self.environ)

                if self.wayf:
                    if query:
                        try:
                            wayf_selected = dict(parse_qs(query))[
                                "wayf_selected"][0]
                        except KeyError:
                            return self._wayf_redirect(came_from)
                        idp_entity_id = wayf_selected
                    else:
                        return self._wayf_redirect(came_from)
                elif self.discosrv:
                    if query:
                        idp_entity_id = _cli.parse_discovery_service_response(
                            query=self.environ.get("QUERY_STRING"))
                    else:
                        sid_ = sid()
                        self.cache.outstanding_queries[sid_] = came_from
                        logger.info("Redirect to Discovery Service function")
                        eid = _cli.config.entity_id
                        rid, loc = _cli.create_discovery_service_request(
                            self.discosrv, eid)
                        return -1, SeeOther(headers=[('Location', loc)])
                else:
                    return -1, NotImplemented("No WAYF or DS present!")

        logger.info("Chosen IdP: '%s'" % idp_entity_id)
        return 0, idp_entity_id

    def _redirect_to_auth(self, _cli, entity_id, came_from, vorg_name=""):
        try:
            _binding, destination = _cli.pick_binding(
                "single_sign_on_service", self.bindings, "idpsso",
                entity_id=entity_id)
            logger.debug("binding: %s, destination: %s" % (_binding,
                                                           destination))
            _sid, req = _cli.create_authn_request(destination, vorg=vorg_name)
            _rstate = rndstr()
            self.cache.relay_state[_rstate] = came_from
            ht_args = _cli.apply_binding(_binding, "%s" % req, destination,
                                         relay_state=_rstate)
            logger.debug("ht_args: %s" % ht_args)
        except Exception, exc:
            logger.exception(exc)
            resp = ServiceError(
                "Failed to construct the AuthnRequest: %s" % exc)
            return resp(self.environ, self.start_response)

        # remember the request
        self.cache.outstanding_queries[_sid] = came_from
        return self.response(_binding, ht_args, dont_send=True)

    def do(self):
        _cli = self.sp

        # Which page was accessed to get here
        came_from = geturl(self.environ)
        logger.debug("[sp.challenge] RelayState >> '%s'" % came_from)

        # Am I part of a virtual organization or more than one ?
        try:
            vorg_name = _cli.vorg._name
        except AttributeError:
            vorg_name = ""

        logger.info("[sp.challenge] VO: %s" % vorg_name)

        # If more than one idp and if none is selected, I have to do wayf
        (done, response) = self._pick_idp(came_from)
        # Three cases: -1 something went wrong or Discovery service used
        #               0 I've got an IdP to send a request to
        #               >0 ECP in progress
        logger.debug("_idp_pick returned: %s" % done)
        if done == -1:
            return response
        elif done > 0:
            self.cache.outstanding_queries[done] = came_from
            return ECP_response(response)
        else:
            entity_id = response
            # Do the AuthnRequest
            try:
                _binding, destination = _cli.pick_binding(
                    "single_sign_on_service", self.bindings, "idpsso",
                    entity_id=entity_id)
                logger.debug("binding: %s, destination: %s" % (_binding,
                                                               destination))
                _sid, req = _cli.create_authn_request(destination, vorg=vorg_name)
                _rstate = rndstr()
                self.cache.relay_state[_rstate] = came_from
                ht_args = _cli.apply_binding(_binding, "%s" % req, destination,
                                             relay_state=_rstate)
                logger.debug("ht_args: %s" % ht_args)
            except Exception, exc:
                logger.exception(exc)
                resp = ServiceError(
                    "Failed to construct the AuthnRequest: %s" % exc)
                return resp(self.environ, self.start_response)

            # remember the request
            self.cache.outstanding_queries[_sid] = came_from
            return self.response(_binding, ht_args)


# ----------------------------------------------------------------------------


#noinspection PyUnusedLocal
def not_found(environ, start_response):
    """Called if no URL matches."""
    resp = NotFound('Not Found')
    return resp(environ, start_response)


# ----------------------------------------------------------------------------

def session(environ, start_response):
    id = environ["PATH_INFO"][9:]
    _info = SESSIONDB[id]
    argv = {"assertion": json.dumps(_info["assertion"], sort_keys=True,
                                    indent=2, separators=(',', ': ')),
            "info": _info["info"]}
    resp = Response(mako_template="session.mako", template_lookup=LOOKUP,
                    headers=[])
    return resp(environ, start_response, **argv)

# ----------------------------------------------------------------------------

# map urls to functions
urls = [
    (r'^Session/(.+)$', session)
]


def add_urls():
    base = "acs"

    urls.append(("%s/post$" % base, (ACS, "post", SP)))
    urls.append(("%s/post/(.*)$" % base, (ACS, "post", SP)))
    urls.append(("%s/redirect$" % base, (ACS, "redirect", SP)))
    urls.append(("%s/redirect/(.*)$" % base, (ACS, "redirect", SP)))
    urls.append((r'^$', (SSO, "do", SP)))

# ----------------------------------------------------------------------------


def application(environ, start_response):
    """
    The main WSGI application. Dispatch the current request to
    the functions from above.

    If nothing matches call the `not_found` function.
    
    :param environ: The HTTP application environment
    :param start_response: The application to run when the handling of the 
        request is done
    :return: The response as a list of lines
    """
    path = environ.get('PATH_INFO', '').lstrip('/')
    logger.info("<application> PATH: '%s'" % path)

    logger.debug("Finding callback to run")
    try:
        for regex, spec in urls:
            match = re.search(regex, path)
            if match is not None:
                if isinstance(spec, tuple):
                    callback, func_name, _sp = spec
                    cls = callback(_sp, environ, start_response, cache=CACHE)
                    func = getattr(cls, func_name)
                    return func()
                else:
                    return spec(environ, start_response)
        if re.match(".*static/.*", path):
            return handleStatic(environ, start_response, path)
        return not_found(environ, start_response)
    except StatusError, err:
        logging.error("StatusError: %s" % err)
        resp = BadRequest("%s" % err)
        return resp(environ, start_response)
    except Exception, err:
        logging.exception("RUN", err)
        return [err]

# ----------------------------------------------------------------------------

PORT = 8092

SERVER_CERT = "pki/server.crt"
SERVER_KEY = "pki/server.key"
CERT_CHAIN = None

if __name__ == '__main__':
    #from wsgiref.simple_server import make_server
    from cherrypy import wsgiserver
    from cherrypy.wsgiserver import ssl_pyopenssl

    _parser = argparse.ArgumentParser()
    _parser.add_argument('-d', dest='debug', action='store_true',
                         help="Print debug information")
    _parser.add_argument('-D', dest='discosrv',
                         help="An ini file containing all the DS:es")
    _parser.add_argument('-s', dest='seed',
                         help="Cookie seed")
    _parser.add_argument("config", help="SAML client config")

    ARGS = {}
    _args = _parser.parse_args()

    SP = Saml2Client(config_file="%s" % _args.config)

    if _args.discosrv:
        cnf = ConfigParser.ConfigParser()
        cnf.read(_args.discosrv)
        ARGS["disco_srvs"] = {}
        for section in cnf.sections():
            name = cnf.get(section, "name")
            url = cnf.get(section, "url")
            ARGS["disco_srvs"][name] = urllib.quote("/DS/%s" % url)

    CACHE = Cache()
    CNFBASE = _args.config
    if _args.seed:
        SEED = _args.seed
    else:
        SEED = "SnabbtInspel"

    POLICY = Policy(
        {
            "default": {"entity_categories": ["swamid", "edugain"]}
        }
    )

    add_urls()

    #srv = make_server('', PORT, application)
    srv = wsgiserver.CherryPyWSGIServer(('0.0.0.0', PORT), application)

    if SERVER_CERT and SERVER_KEY:
        srv.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(SERVER_CERT,
                                                         SERVER_KEY,
                                                         CERT_CHAIN)

    print "SP listening on port: %s" % PORT
    #srv.serve_forever()
    try:
        srv.start()
    except KeyboardInterrupt:
        srv.stop()