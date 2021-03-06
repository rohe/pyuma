import base64
import json
import logging
import socket
import traceback
import sys

from oic.extension.provider import Provider as OAUTH2Provider

from oic.oauth2 import MessageException
from oic.oauth2 import TokenErrorResponse
from oic.oauth2.provider import Endpoint
from oic.oauth2.provider import endpoint_ava

from oic.oic import rndstr
from oic.oic.provider import Provider as OIDCProvider
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import AuthorizationEndpoint

from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.authn.user import FailedAuthentication
from oic.utils.authn.user import ToOld
from oic.utils.http_util import BadRequest, factory
from oic.utils.http_util import NotFound
from oic.utils.http_util import NoContent
from oic.utils.http_util import Created
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import Response
from oic.utils.keyio import KeyJar
from oic.utils.time_util import utc_time_sans_frac

from uma.adb import ADB
from uma.client import UMA_SCOPE
from uma.message import AuthorizationDataRequest
from uma.message import AuthorizationDataResponse
from uma.message import ErrorResponse
from uma.message import IntrospectionRequest
from uma.message import IntrospectionResponse
from uma.message import PermissionRegistrationRequest
from uma.message import PermissionRegistrationResponse
from uma.message import ProviderConfiguration
from uma.message import RPTRequest
from uma.message import RQP_CLAIMS_GRANT_TYPE
from uma.rsdb import UnknownObject

__author__ = 'rolandh'

logger = logging.getLogger(__name__)

DB_NAME = "uma"
COLLECTION = "authz"
STR = 5 * "_"


class NoMatchingSession(Exception):
    pass


class AuthnFailed(Exception):
    pass


class UnknownResourceSet(Exception):
    pass


class ResourceSetRegistrationEndpoint(Endpoint):
    etype = "resource_set_registration"
    url = "resource_set_registration"


class IntrospectionEndpoint(Endpoint):
    etype = "introspection"
    url = "introspection"


class PermissionRegistrationEndpoint(Endpoint):
    etype = "permission_registration"
    url = "permission_registration"


class RPTEndpoint(Endpoint):
    etype = "rpt"
    url = "rpt"


class DynamicClientEndpoint(Endpoint):
    etype = "dynamic_client"
    url = "dynamic_client"


class RequestingPartyClaimsEndpoint(Endpoint):
    etype = "requesting_party_claims"
    url = "requesting_party_claims"


class ClientInfoEndpoint(Endpoint):
    etype = "clientinfo"
    url = "clientinfo"


RSR_PATH = "%s/resource_set" % ResourceSetRegistrationEndpoint().etype
PLEN = len(RSR_PATH)


def eval_scopes(permission, allow_scopes):
    _scopes = []

    for scope in permission["scopes"]:
        if scope in allow_scopes:
            _scopes.append(scope)
        else:
            for asc in allow_scopes:
                if scope.startswith(asc):
                    _scopes.append(scope)
                    break

    if not _scopes:  # Check if the the asked for is less specific
        for asc in allow_scopes:
            for scope in permission["scopes"]:
                if asc.startswith(scope):
                    _scopes.append(asc)

    return _scopes


def client_authentication(sdb, authn=""):
    """

    """
    if not authn:
        raise AuthnFailed()
    else:
        try:
            assert authn.startswith("Bearer ")
        except AssertionError:
            raise AuthnFailed()

        token = authn[7:]
        try:
            _info = sdb.read(token)
            subject = _info["authn_event"].uid
            client_id = _info["client_id"]
        except KeyError:
            raise AuthnFailed()

    return subject, client_id


class Session(object):
    # Storage for access tokens
    def __init__(self, lifetime=3600):
        self.db = {}
        self.lifetime = lifetime

    def get(self, item):
        _info = self.db[item]
        now = utc_time_sans_frac()
        if _info["expires_at"] < now:
            raise ToOld("Already expired")

        if "permissions" in _info:
            _perms = []
            for perm in _info["permissions"]:
                if perm["expires_at"] > now:
                    _perms.append(perm)

            if len(_perms) != len(_info["permissions"]):
                _info["permissions"] = _perms

        return _info

    def set(self, token, permissions=""):
        now = utc_time_sans_frac()

        _info = {
            "expires_at": now + self.lifetime,
            "issued_at": now,
        }
        if permissions:
            _info["permissions"] = permissions

        self.db[token] = _info

    def add_permissions(self, token, permission):
        try:
            self.db[token]["permissions"].append(permission)
        except KeyError:
            self.db[token]["permissions"] = [permission]

    def update(self, token, **kwargs):
        self.db[token].update(kwargs)


def get_requester(foo):
    return foo


def authenticated_call(sdb, func, authn, request=None, **kwargs):
    try:
        entity, client_id = client_authentication(sdb, authn)
    except AuthnFailed:
        return Unauthorized()
    else:
        kwargs["entity"] = entity
        kwargs["client_id"] = client_id
        if request:
            kwargs["request"] = request
    return func(**kwargs)



class UmaAS(object):
    endp = [AuthorizationEndpoint, DynamicClientEndpoint,
            IntrospectionEndpoint, PermissionRegistrationEndpoint,
            RequestingPartyClaimsEndpoint, ResourceSetRegistrationEndpoint,
            RPTEndpoint, TokenEndpoint, ClientInfoEndpoint]

    def __init__(self, configuration=None, baseurl=""):
        self.keyjar = None
        self.conf_info = configuration or {}
        self.rpt = {}
        self.baseurl = baseurl
        if not self.baseurl.endswith("/"):
            self.baseurl += "/"
        self.session = Session()
        self.eid2rpt = {}
        self.get_requester = get_requester
        self.rsdb = {}
        try:
            self.rpt_lifetime = self.conf_info['rpt_lifetime']
        except KeyError:
            self.rpt_lifetime = 0  # For ever

    def endpoints(self):
        for endp in self.endp:
            yield endp(None).name

    def services(self):
        for endp in self.endp:
            yield endp.etype

    def get_adb(self, entity_id):
        try:
            return self.rsdb[entity_id]
        except KeyError:
            # Should really be done together with RS/client registration
            self.rsdb[entity_id] = ADB(self.keyjar, self.rpt_lifetime,
                                       self.baseurl, entity_id,RSR_PATH)
            return self.rsdb[entity_id]

    # def rpt_endpoint_(self, requestor, client_id, **kwargs):
    # """
    # The endpoint URI at which the client asks the authorization server for
    # a RPT.
    #     """
    #     #res = self.client_authentication(authn)
    #     #if isinstance(res, Response):
    #     #    return res
    #
    #     # create RPT, just overwrites whatever was there before
    #     rpt = rndstr(32)
    #     self.rpt[rpt] = {"requestor": requestor, "client_id": client_id}
    #     self.session.set(rpt)
    #
    #     msg = RPTResponse(rpt=rpt)
    #     return Response(msg.to_json(), content="application/json")

    def resource_set_registration_endpoint_(self, owner, path, method,
                                            client_id, body="", if_match="",
                                            **kwargs):
        """
        The endpoint at which the resource server handles resource sets
        descriptions.

        :param owner: The entity that controls the resource set
        :param path: The path for the HTTP request
        :param method: HTTP method
        :param body: The resource set registration message
        :param client_id: Which client I'm talking to
        :param if_match: The HTTP If-Match header if any
        :param kwargs: possible other arguments
        :returns: A Response instance
        """

        # path must be /resource_set/{rsid} or /resource_set
        # Path may or may not start with '/'
        if path.startswith("/"):
            assert path[1:].startswith(RSR_PATH)
            rsid = path[PLEN + 1:]
        else:
            assert path.startswith(RSR_PATH)
            rsid = path[PLEN:]

        if rsid.startswith("/"):
            rsid = rsid[1:]

        # user names are not globally unique, so I have to make such an
        # identifier
        logger.debug("handling resource set belonging to '%s'" % owner)

        adb = self.get_adb(client_id)
        code, msg, kwargs = adb.resource_set_registration(method, owner,
                                                          body=body, rsid=rsid)
        return factory(code, msg, **kwargs)

    def _collapse(self, items, ressrv_id):
        referenced = {}
        ibrsid = {}
        adb = self.get_adb(ressrv_id)

        for item in items:
            try:
                for rsid in item["subsets"]:
                    if rsid not in referenced:
                        referenced[rsid] = 1
                    else:
                        referenced[rsid] += 1
            except KeyError:
                pass

            _rsid = adb.map_id_rsid[item["_id"]]
            if _rsid not in referenced:
                referenced[_rsid] = 0
            ibrsid[_rsid] = item

        res = []
        for key, val in list(referenced.items()):
            if val == 0:
                res.append(ibrsid[key])

        return res

    def resource_sets_by_user(self, owner, client_id, collapse=False):
        """
        :param owner: The owner of the resource sets
        :param client_id: Client ID of the resource server
        :param collapse: ...
        :return: A list of ResourceSetDescriptions
        """
        res = []
        adb = self.get_adb(client_id)
        try:
            rss = adb.resource_set.list(owner)
        except KeyError:
            return []

        for _id in rss:
            try:
                res.append(adb.resource_set.read(owner, _id))
            except Exception:
                raise

        if collapse:
            res = self._collapse(res, client_id)

        return res

    def permits_by_user(self, owner, client_id):
        """
        :param owner: The owner of the resource
        :param client_id: The client id of the resource server
        :return: A dictionary with requestors as keys and permissions as values
        """
        adb = self.get_adb(client_id)
        return adb.permit.get_accepted(owner)

    def authz_session_info(self, token):
        pass

    def introspection_endpoint_(self, user, **kwargs):
        """
        The endpoint URI at which the resource server introspects an RPT
        presented to it by a client.
        """

        request = kwargs["request"]
        logger.debug("requestor: %s, request: %s" % (user, request))
        ir = IntrospectionRequest().from_json(request)
        adb = self.get_adb(kwargs["client_id"])
        try:
            try:
                # requestor = self.rpt[ir["token"]]["requestor"]
                perms = adb.permit.get_accepted_by_rpt(user, ir["token"])
            except KeyError:
                response = BadRequest()
            else:
                if perms:
                    irep = IntrospectionResponse(
                        active=True,
                        exp=perms[0]["exp"],
                        permissions=perms
                    )
                    logger.debug("response: %s" % irep.to_json())
                    response = Response(irep.to_json(),
                                        content="application/json")
                else:
                    logger.info("No permissions bound to this RPT")
                    response = BadRequest()
        except ToOld:
            logger.info("RPT expired")
            irep = IntrospectionResponse(valid=False)
            response = Response(irep.to_json(), content="application/json")
        except KeyError:
            response = BadRequest()

        return response

    def to_prr(self, request, ressrv):
        """
        Trying to register a permission for an unknown resource set will
         fail

        :param request: JSON encoded permission request or list of permission
            requests
        :param ressrv: Client id of the resource server
        """
        decoded_req = json.loads(request)
        pr_req = []
        adb = self.get_adb(ressrv)
        if isinstance(decoded_req, list):
            for item in decoded_req:
                if item['resource_set_id'] in adb.resource_set.rsid2oid:
                    pr_req.append(PermissionRegistrationRequest(**item))
                else:
                    logger.warning(
                        'Trying to register permission for unknown resource set')
        else:
            if decoded_req['resource_set_id'] in adb.resource_set.rsid2oid:
                pr_req.append(PermissionRegistrationRequest(**decoded_req))
            else:
                logger.warning(
                    'Trying to register permission for unknown resource set')

        return pr_req

    def permission_registration_endpoint_(self, request, **kwargs):
        """
        The endpoint URI at which the resource server registers a
        client-requested permission with the authorization server.
        This is a proposed permission waiting for the user to accept it.

        :param request: The permission registration request
        :return: HTTP Response
        """

        adb = self.get_adb(kwargs['client_id'])
        prr = self.to_prr(request, kwargs['client_id'])
        if prr:
            _ticket = adb.ticket_factory.pack(aud=[kwargs['client_id']],
                                              type='ticket')
            logging.debug("Registering permission request: %s" % request)
            adb.permission_requests[_ticket] = prr
            resp = PermissionRegistrationResponse(ticket=_ticket)

            return Created(resp.to_json(), content="application/json")
        else:
            return BadRequest("Can't register permission for unknown resource")

    def requesting_party_claims_endpoint(self, request="", **kwargs):
        """
        The endpoint at which the resource server gathers the consent of
        the end-user resource owner or the client gathers the consent of the
        end-user requesting party, if the "authorization_code" grant type is
        used.
        """
        pass

    def dynamic_client_endpoint(self, request="", **kwargs):
        pass

    def token_endpoint(self, request="", **kwargs):
        pass

    def authorization_endpoint(self, request="", **kwargs):
        pass

    @staticmethod
    def token_scope_check(areq, info):
        """
        verifies that the scope that is demanded for the access token is
        one that I'm comfortable with.

        :param areq: AccessTokenRequest
        :param info: What's in the session db
        :return: None if OK otherwise and error response.
        """
        try:
            assert areq["scope"] in info["scope"]
        except AssertionError:
            logger.error("Not the same scope as for the AuthzRequest")
            err = TokenErrorResponse(error="invalid_scope")
            return Response(err.to_json(), content="application/json")

        try:
            assert areq["scope"] in list(UMA_SCOPE.values())
        except AssertionError:
            logger.error("Asked for scope which I don't deal with")
            err = TokenErrorResponse(error="invalid_scope")
            return Response(err.to_json(), content="application/json")

        return None

    def create_uma_providerinfo(self, pcr_class=ProviderConfiguration):
        kwargs = dict([(k, v) for k, v in list(self.conf_info.items())
                       if k in pcr_class.c_param])
        _response = pcr_class(**kwargs)

        for endp in UmaAS.endp:
            _response.update(endpoint_ava(endp, self.baseurl))

        logger.debug("provider_info_response: %s" % (_response.to_dict(),))
        return _response

    # noinspection PyUnusedLocal
    def providerinfo_endpoint_(self, handle="", **kwargs):
        logger.debug("@providerinfo_endpoint")
        try:
            _response = self.create_uma_providerinfo()

            headers = [("Cache-Control", "no-store"), ("x-ffo", "bar")]
            # if handle:
            #     (key, timestamp) = handle
            #     if key.startswith(STR) and key.endswith(STR):
            #         cookie = self.cookie_func(key, self.cookie_name, "pinfo",
            #                                   self.sso_ttl)
            #         headers.append(cookie)

            resp = Response(_response.to_json(), content="application/json",
                            headers=headers)
        except Exception as err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            resp = Response(message, content="html/text")

        return resp

    def get_subsets(self, owner, requestor, scopes, client_id):
        res = {}
        adb = self.get_adb(client_id)
        try:
            permits = adb.permit.get_permit_by_requestor(owner, requestor)
        except KeyError:
            return res

        for permit, (_scopes, time_stamp) in list(permits.items()):
            _scs = []
            for scope in scopes:
                try:
                    assert scope in _scopes
                except AssertionError:
                    pass
                else:
                    _scs.append(scope)
            if _scs:
                res[permit] = _scs
        return res

    def rpt_endpoint_(self, entity, client_id, **kwargs):
        """
        Registers an Authorization Description

        :param entity: Who's on the other side
        :param client_id: The UMA client
        :return: A Response instance
        """
        adb = self.get_adb(client_id)
        adr = AuthorizationDataRequest().from_json(kwargs["request"])
        rpt = adb.issue_rpt(adr['ticket'], {'sub': entity})
        rsp = AuthorizationDataResponse(rpt=rpt)
        return Response(rsp.to_json())

    def name2id(self, owner, rsid, client_id):
        adb = self.get_adb(client_id)
        obj = adb.resource_set.read(owner, rsid)
        return obj["_id"]

    def remove_permission_request(self, owner, requestor, resource_name,
                                  client_id):
        """
        :param owner: The resource owner
        :param requestor: The SP entity ID
        :param resource_name: The name of the resource set
        :param client_id: Client id of the resource server
        """
        _id = self.name2id(owner, resource_name, client_id)
        adb = self.get_adb(client_id)
        try:
            adb.permit.delete_request(owner, requestor, _id)
        except KeyError:
            pass

        try:
            owner = "%s@%s" % (owner, requestor)
            rm_rpt = adb.permit.rm_accepted(owner, _id)
        except KeyError:
            pass
        else:
            for _rpt in rm_rpt:
                # immediate expiration
                self.session.update(_rpt, expires_at=0)

    def store_permission(self, owner, permission, client_id):
        """
        Store permissions given by <owner> to <user>

        :param owner: The resource owner
        :param permission: dictionary with Resource set IDs as keys and scopes
            as values
        :param client_id: The Resource Servers client_id
        """

        logger.info("store: ({}, {})".format(owner, permission))

        adb = self.get_adb(client_id)
        return adb.store_permission(permission=permission, owner=owner)

    def read_permission(self, owner, perm_id, client_id):
        """
        :param owner:
        :param: perm_id: Permission ID
        :param client_id:
        :return: A PermissionDescription instance
        """
        adb = self.get_adb(client_id)
        return adb.read_permission(owner, perm_id)

    def rec_rm_permission(self, owner, requestor, rsid, client_id):
        """
        If the resource set is a complex set, remove all subset permissions
        :param owner: The owner of the resource
        :param requestor: Who the permission is applying to
        :param rsid: The resource set name
        :param client_id: Client id for the resource server
        """
        adb = self.get_adb(client_id)
        rs = adb.resource_set.read(owner, rsid)
        if "subsets" in rs:
            for ss in rs["subsets"]:
                self.rec_rm_permission(owner, requestor, ss, client_id)
        try:
            adb.permit.delete_request(owner, requestor, rsid)
        except KeyError:
            pass

    def rm_permission(self, user, requestor, rsid, client_id):
        """
        If the resource set is a complex set, remove all subset permissions
        :param user: The owner of the resource
        :param requestor: Who the permission is applying to
        :param rsid: The resource set name
        :param client_id: Client id for the resource server
        """
        logger.info("remove: (%s, %s, %s)" % (user, requestor, rsid))
        self.rec_rm_permission(user, requestor, rsid, client_id)
        return True

    def rsid_permits(self, user, requestor, client_id):
        adb = self.get_adb(client_id)
        return adb.permit.pending_permission_requests(user, requestor)


# ----------------------------------------------------------------------------


class OAuth2UmaAS(OAUTH2Provider, UmaAS):
    def __init__(self, name, sdb, cdb, authn_broker, authz,
                 client_authn, symkey, urlmap=None, keyjar=None,
                 hostname="", configuration=None, base_url="",
                 client_authn_methods=None, authn_at_registration="",
                 client_info_url="", secret_lifetime=86400,
                 default_acr=""):

        OAUTH2Provider.__init__(self, name, sdb, cdb, authn_broker, authz,
                                client_authn, symkey=symkey, urlmap=urlmap,
                                client_authn_methods=client_authn_methods,
                                authn_at_registration=authn_at_registration,
                                client_info_url=client_info_url,
                                secret_lifetime=secret_lifetime)
        UmaAS.__init__(self, configuration, baseurl=base_url)

        if keyjar:
            self.keyjar = keyjar
        else:
            self.keyjar = KeyJar()

        self.hostname = hostname or socket.gethostname
        self.jwks_uri = []
        self.endp = UmaAS.endp[:]
        self.endp.extend(OAUTH2Provider.endp)
        self.default_acr = default_acr

    def set_authn_broker(self, authn_broker):
        self.authn_broker = authn_broker
        for meth in self.authn_broker:
            meth.srv = self
        if authn_broker:
            self.cookie_func = authn_broker[0].create_cookie
        else:
            self.cookie_func = None

    def authz_session_info(self, token):
        if self.sdb.is_valid(token):
            return self.sdb.read(token)
        else:
            raise NoMatchingSession()

    def rpt_endpoint(self, authn, **kwargs):
        """
        :param authn: authentication information
        """
        try:
            entity, client_id = client_authentication(self.sdb, authn)
        except AuthnFailed:
            return Unauthorized()

        return self.rpt_endpoint_(entity, client_id, **kwargs)

    def introspection_endpoint(self, request="", **kwargs):
        try:
            entity, client_id = client_authentication(self.sdb, kwargs["authn"])
        except AuthnFailed:
            return Unauthorized()
        return self.introspection_endpoint_(entity, request=request,
                                            client_id=client_id, **kwargs)

    def providerinfo_endpoint(self, handle="", **kwargs):
        return self.providerinfo_endpoint_(handle, **kwargs)

    def resource_set_registration_endpoint(self, path, method, body="",
                                           if_match="", **kwargs):
        try:
            entity, client_id = client_authentication(self.sdb, kwargs["authn"])
        except AuthnFailed:
            return Unauthorized()

        return self.resource_set_registration_endpoint_(
            owner=entity, path=path, method=method, client_id=client_id,
            body=body, if_match=if_match, **kwargs)

    def dynamic_client_endpoint(self, request="", environ=None, **kwargs):
        return self.registration_endpoint(request=request, environ=environ,
                                          **kwargs)

    def permission_registration_endpoint(self, request="", authn="", **kwargs):
        try:
            entity, client_id = client_authentication(self.sdb, authn)
        except AuthnFailed:
            return Unauthorized()

        return self.permission_registration_endpoint_(
            owner=entity, request=request, client_id=client_id, **kwargs)

    # def authorization_data_request_endpoint(self, request="", authn="",
    # **kwargs):
    # try:
    # owner, client_id = client_authentication(self.sdb, authn)
    #     except AuthnFailed:
    #         return Unauthorized()
    #
    #     return self.authorization_data_request_endpoint_(request, owner,
    #                                                      client_id,
    #                                                      **kwargs)

    def uma_providerinfo_endpoint(self, handle="", **kwargs):
        return self.providerinfo_endpoint_(handle, **kwargs)


class OidcDynRegUmaAS(UmaAS):
    def __init__(self, base, sdb, cdb, authn_broker, userinfo, authz,
                 client_authn, symkey, urlmap=None, keyjar=None,
                 hostname="", configuration=None, ca_certs="",
                 template_lookup=None, verify_login_template=None,
                 base_url=""):

        UmaAS.__init__(self, configuration, baseurl=base_url)

        self.sdb = sdb
        if keyjar:
            self.keyjar = keyjar
        else:
            self.keyjar = KeyJar()

        self.cookie_name = self.__class__.__name__
        self.hostname = hostname or socket.gethostname
        self.jwks_uri = []
        self.endp = UmaAS.endp[:]

        self.srv = {
            "oidc": OIDCProvider(
                base, sdb, cdb, authn_broker, userinfo,
                authz, client_authn, symkey, urlmap, ca_certs,
                keyjar, hostname, template_lookup, verify_login_template),
            "dyn_reg": OAUTH2Provider(
                base, sdb, cdb, authn_broker, authz, client_authn, symkey,
                urlmap, client_authn_methods=CLIENT_AUTHN_METHOD),
            "oauth": OAUTH2Provider(
                base, sdb, cdb, authn_broker, authz, client_authn, symkey,
                urlmap, ca_bundle=ca_certs,
                client_authn_methods=CLIENT_AUTHN_METHOD)
        }

        self.endp.extend(self.srv["oidc"].endp)
        self.endp = list(set(self.endp))
        self.srv["oidc"].jwks_uri = self.jwks_uri
        self.srv["oidc"].baseurl = base

        self.request2endpoint = dict(
            [(e.__class__.__name__, "%s_endpoint" % e.etype) for e in
             self.endp])

        self.kid = {"sig": {}, "enc": {}}

    def user_from_bearer_token(self, authn=""):
        if not authn:
            raise AuthnFailed()
        else:
            assert authn.startswith("Bearer ")
            token = authn[7:]
            return self.sdb.read(token)["sub"]

    def authz_session_info(self, authn=""):
        if not authn:
            raise AuthnFailed()
        else:
            assert authn.startswith("Bearer ")
            token = authn[7:]
            if self.sdb.is_valid(token):
                return self.sdb.read(token)

        raise NoMatchingSession()

    def rpt_endpoint(self, authn, **kwargs):
        """
        :param authn: authentication information
        """
        return authenticated_call(self.sdb, self.rpt_endpoint_, authn,
                                  **kwargs)

    def introspection_endpoint(self, request="", authn="", **kwargs):
        return authenticated_call(self.sdb, self.introspection_endpoint_,
                                  authn, request, **kwargs)

    def uma_providerinfo_endpoint(self, handle="", **kwargs):
        return self.providerinfo_endpoint_(handle, **kwargs)

    def oidc_providerinfo_endpoint(self, handle="", **kwargs):
        return self.srv["oidc"].providerinfo_endpoint(handle, **kwargs)

    def resource_set_registration_endpoint(self, authn, **kwargs):

        return authenticated_call(
            self.sdb, self.resource_set_registration_endpoint_, authn, **kwargs)

    def oidc_registration_endpoint(self, request="", environ=None, **kwargs):
        return self.srv["oidc"].registration_endpoint(request, environ,
                                                      **kwargs)

    def oauth_registration_endpoint(self, request="", environ=None, **kwargs):
        return self.srv["dyn_reg"].registration_endpoint(request, environ,
                                                         **kwargs)

    def permission_registration_endpoint(self, request="", authn="", **kwargs):
        return authenticated_call(
            self.sdb, self.permission_registration_endpoint_, authn, request,
            **kwargs)

    def authorization_endpoint(self, request="", **kwargs):
        # return self.srv["oidc"].authorization_endpoint(request, **kwargs)
        return self.srv["oauth"].authorization_endpoint(request, **kwargs)

    def token_endpoint(self, request="", **kwargs):
        # return self.srv["oidc"].token_endpoint(request, **kwargs)
        return self.srv["oauth"].token_endpoint(request=request, **kwargs)

    def client_info_endpoint(self, request, environ, method, query):
        _srv = self.srv["dyn_reg"]
        return _srv.client_info_endpoint(request, environ, method, query)

    def rpt_token_endpoint(self, authn, request):
        areq = RPTRequest().deserialize(request, "json")

        try:
            client_id = self.srv["oauth"].client_authn(self.srv["oauth"], areq,
                                                       authn)
        except FailedAuthentication as err:
            err = TokenErrorResponse(error="unauthorized_client",
                                     error_description="%s" % err)
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        try:
            assert areq["grant_type"] == RQP_CLAIMS_GRANT_TYPE
        except AssertionError:
            err = TokenErrorResponse(error="invalid_request",
                                     error_description="Wrong grant type")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        requesting_party_uid = ""
        for rqp_claims in areq["claim_tokens"]:
            if rqp_claims["format"] == "json":
                claims = json.loads(
                    base64.urlsafe_b64decode(
                        rqp_claims["token"].encode("ascii")).decode("utf-8"))
                if "uid" in claims:
                    requesting_party_uid = claims["uid"]
                    break

        if not requesting_party_uid:
            err = TokenErrorResponse(
                error="invalid_request",
                error_description="No requesting party uid provided")
            return Response(err.to_json(), content="application/json",
                            status="401 Unauthorized")

        return self.rpt_endpoint_(requesting_party_uid, client_id,
                                  request=request)
