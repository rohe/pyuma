import logging
import socket
import traceback
import sys
import time

from oic.oauth2.dynreg import Provider as OAUTH2Provider
from oic.oic.provider import Provider as OIDCProvider
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import AuthorizationEndpoint

from oic.oauth2 import MessageException
from oic.oauth2 import TokenErrorResponse
from oic.oauth2 import rndstr
from oic.oauth2 import dynreg
from oic.oauth2.provider import Endpoint
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.authn.user import ToOld
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Created
from oic.utils.http_util import Unauthorized
from oic.utils.http_util import Response
from oic.utils.keyio import KeyJar
#from uma.authzdb import AuthzDB

from uma.client import UMA_SCOPE
from uma.message import IntrospectionRequest
from uma.message import AuthzDescription
from uma.message import AuthorizationDataRequest
from uma.message import IntrospectionResponse
from uma.message import PermissionRegistrationResponse
from uma.message import ProviderConfiguration
from uma.resource_set import ResourceSetDB

__author__ = 'rolandh'

logger = logging.getLogger(__name__)

DB_NAME = "uma"
COLLECTION = "authz"
STR = 5 * "_"


def safe_name(string):
    return string.replace(".", "__")


class NoMatchingSession(Exception):
    pass


class AuthnFailed(Exception):
    pass


class UnknownResourceSet(Exception):
    pass


class ResourceSetRegistrationEndpoint(Endpoint):
    etype = "resource_set_registration"


class IntrospectionEndpoint(Endpoint):
    etype = "introspection"


class PermissionRegistrationEndpoint(Endpoint):
    etype = "permission_registration"


class RPTEndpoint(Endpoint):
    etype = "rpt"


class DynamicClientEndpoint(Endpoint):
    etype = "dynamic_client"


class RequestingPartyClaimsEndpoint(Endpoint):
    etype = "requesting_party_claims"


class ClientInfoEndpoint(Endpoint):
    etype = "clientinfo"


RSR_PATH = "%s/resource_set/" % ResourceSetRegistrationEndpoint(None).etype
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
            subject = sdb.read(token)["sub"]
            client_id = sdb.read(token)["client_id"]
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
        now = time.time()
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
        now = time.time()

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


class Permission(object):
    def __init__(self):
        self.db = {}

    def init_owner(self, owner):
        self.db[owner] = {
            "request": {},
            "permit": {},
            "accepted": {},
            "permitted_at": {}
        }

    def add_request(self, owner, ticket, req):
        if owner not in self.db:
            self.init_owner(owner)

        self.db[owner]["request"][ticket] = req

    def get_request(self, owner, ticket):
        return self.db[owner]["request"][ticket]

    def get_outstanding_requests(self, owner):
        """
        :param owner:
        :return: A dictionary of tickets and requests
        """
        return self.db[owner]["request"]

    def del_request(self, owner, ticket):
        """
        Remove a specific permission request
        :param owner: The owner of the resource
        :param ticket: The ticket returned when the request was registered
        """
        del self.db[owner]["request"][ticket]

    def set_permit(self, owner, requestor, resource_id, scopes=None):
        if owner not in self.db:
            self.init_owner(owner)

        _perm = self.db[owner]["permit"]

        _val = (scopes, time.time())
        try:
            _perm[requestor][resource_id] = _val
        except KeyError:
            try:
                _perm[requestor] = {resource_id: _val}
            except KeyError:
                self.db[owner]["permit"] = {requestor: {resource_id: _val}}

    def get_permit(self, owner, requestor, resource_id):
        """
        :return: A tuple (scopes, timestamp)
        """
        return self.db[owner]["permit"][requestor][resource_id]

    def get_permit_by_requestor(self, owner, requestor):
        """
        :return: A dictionary with resource_id as keys and the tuple
        (scopes, timestamp) as values
        """
        return self.db[owner]["permit"][requestor]

    def delete_permit(self, owner, requestor, resource_id):
        del self.db[owner]["permit"][requestor][resource_id]

    def delete_permit_by_resource_id(self, owner, resource_id):
        for req, spec in self.db[owner]["permit"].items():
            if resource_id in spec:
                self.delete_permit(owner, req, resource_id)

    def get_permits(self, owner):
        """
        :param owner: The owner of the resource
        :return: A dictionary with requestors as keys and permissions as keys
        """
        return self.db[owner]["permit"]

    def set_accepted(self, owner, rpt, authz_desc):
        if owner not in self.db:
            self.init_owner(owner)

        try:
            self.db[owner]["accepted"][rpt].append(authz_desc)
        except KeyError:
            self.db[owner]["accepted"] = {rpt: [authz_desc]}

    def get_accepted(self, owner, rpt):
        return self.db[owner]["accepted"][rpt]

    def rm_accepted(self, owner, rsid):
        _remove = []
        for rpt, desc in self.db[owner]["accepted"].items():
            if desc["resource_set_id"] == rsid:
                _remove.append(rpt)

        for rpt in _remove:
            del self.db[owner]["accepted"][rpt]

        return _remove

    def get_owner_of_request_target(self, requestid):
        for owner, item in self.db.items():
            for key, req in item["request"].items():
                if key == requestid:
                    return owner

    def get_rsid_permits(self, owner, requestor):
        """
        :return: list of resource set ids
        """
        try:
            return self.db[owner]["permit"][requestor].keys()
        except KeyError:
            return []


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
        kwargs["request"] = request
    return func(entity, **kwargs)


class UmaAS(object):
    endp = [AuthorizationEndpoint, DynamicClientEndpoint,
            IntrospectionEndpoint, PermissionRegistrationEndpoint,
            RequestingPartyClaimsEndpoint, ResourceSetRegistrationEndpoint,
            RPTEndpoint, TokenEndpoint, ClientInfoEndpoint]

    def __init__(self, configuration=None, baseurl=""):

        self.conf_info = configuration or {}
        self.resource_set = ResourceSetDB(DB_NAME, COLLECTION)
        self.rpt = {}
        self.baseurl = baseurl
        if not self.baseurl.endswith("/"):
            self.baseurl += "/"
        self.session = Session()
        self.permit = Permission()
        self.map_rsid_id = {}
        self.map_id_rsid = {}
        self.map_user_id = {}
        self.eid2rpt = {}
        self.get_requester = get_requester

    def endpoints(self):
        for endp in self.endp:
            yield endp(None).name

    def services(self):
        for endp in self.endp:
            yield endp.etype

    # def rpt_endpoint_(self, requestor, client_id, **kwargs):
    #     """
    #     The endpoint URI at which the client asks the authorization server for
    #     a RPT.
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

    def resource_set_registration_endpoint_(self, entity, path, client_id,
                                            method, body, if_match,
                                            **kwargs):
        """
        The endpoint at which the resource server handles resource sets
        descriptions.

        :param path:
        :param method: HTTP method
        :param body: The resource set registration message
        :param owner: The Owner of the resource
        :paran client_id: Which client I'm talking to
        :param if_match: The HTTP If-Match header if any
        :param kwargs: possible other arguments
        :returns: A Response instance
        """

        # path should be /resource_set/{rsid}
        # Path may or may not start with '/'
        if path.startswith("/"):
            assert path[1:].startswith(RSR_PATH)
            rsid = path[PLEN+1:]
        else:
            assert path.startswith(RSR_PATH)
            rsid = path[PLEN:]

        if rsid.startswith("/"):
            rsid = rsid[1:]

        _user = safe_name("%s:%s" % (entity, client_id))
        logger.debug("handling resource set belonging to '%s'" % _user)
        self.resource_set.set_collection(_user)
        if method == "PUT":
            if if_match:  # Update
                func = self.resource_set.update
                args = {"data": body, "mid": if_match}
            else:  # Create
                func = self.resource_set.create
                args = {"data": body}
        elif method == "GET":
            if if_match:  # List
                func = self.resource_set.update
                args = {"mid": if_match}
            else:  # Read
                try:
                    mid = self.map_rsid_id[rsid]
                except KeyError:
                    raise UnknownResourceSet(rsid)
                func = self.resource_set.read
                args = {"mid": mid}
        elif method == "DELETE":
            try:
                mid = self.map_rsid_id[rsid]
            except KeyError:
                raise UnknownResourceSet(rsid)
            func = self.resource_set.delete
            args = {"mid": mid}
        else:
            return BadRequest("Message error")

        logger.debug("operation: %s" % func)
        logger.debug("operation args: %s" % (args,))
        try:
            body = func(**args)
        except MessageException:
            response = BadRequest("Message error")
        else:
            if func == self.resource_set.create:
                _id = body["_id"]
                self.map_rsid_id[rsid] = _id
                self.map_id_rsid[_id] = rsid
                try:
                    self.map_user_id[entity].append(_id)
                except KeyError:
                    self.map_user_id[entity] = [_id]
            elif func == self.resource_set.delete:
                # As a side effect all permissions assigned that references
                # this resource set should be deleted
                self.permit.delete_permit_by_resource_id(entity, rsid)

            response = Response(body.to_json(), content="application/json")

        return response

    def _collapse(self, items):
        referenced = {}
        ibrsid = {}
        for item in items:
            try:
                for rsid in item["subsets"]:
                    if not rsid in referenced:
                        referenced[rsid] = 1
                    else:
                        referenced[rsid] += 1
            except KeyError:
                pass

            _rsid = self.map_id_rsid[item["_id"]]
            if not _rsid in referenced:
                referenced[_rsid] = 0
            ibrsid[_rsid] = item

        res = []
        for key, val in referenced.items():
            if val == 0:
                res.append(ibrsid[key])

        return res

    def resource_sets_by_user(self, user, collapse=False):
        """
        :param user: The user for which resource set descriptions has been
            registered.
        :return: A list of ResourceSetDescriptions
        """
        res = []
        for _id in self.map_user_id[user]:
            try:
                res.append(self.resource_set.read(_id))
            except Exception:
                raise

        if collapse:
            res = self._collapse(res)

        return res

    def resource_set_tree_by_rsid(self, rsid):
        rs = self.resource_set.read(self.map_rsid_id[rsid])
        _name = rs["name"].split("/")[-1]
        try:
            _rsids = rs["subsets"]
        except KeyError:
            return rsid, _name
        else:
            res = {}
            for _rsid in _rsids:
                _rs = self.resource_set_tree_by_rsid(_rsid)
                try:
                    res.update(_rs)
                except ValueError:
                    try:
                        res.append(_rs)
                    except AttributeError:
                        res = [_rs]

            return {(rsid, _name): res}

    def resource_set_name(self, rsid):
        rs = self.resource_set.read(self.map_rsid_id[rsid])
        return rs["name"]

    def permits_by_user(self, owner):
        """
        :param owner: The owner of the resource
        :return: A dictionary with requestors as keys and permissions as values
        """
        return self.permit.get_permits(owner)

    def authz_session_info(self, token):
        pass

    def introspection_endpoint_(self, entity, **kwargs):
        """
        The endpoint URI at which the resource server introspects an RPT
        presented to it by a client.
        """

        request = kwargs["request"]
        logger.debug("requestor: %s, request: %s" % (entity, request))
        ir = IntrospectionRequest().from_json(request)
        try:
            _info = self.session.get(ir["token"])
            irep = IntrospectionResponse(
                valid=True,
                expires_at=_info["expires_at"],
            )
            try:
                #requestor = self.rpt[ir["token"]]["requestor"]
                perms = self.permit.get_accepted(entity, ir["token"])
            except KeyError:
                pass
            else:
                if perms:
                    irep["permissions"] = perms
                else:
                    logger.info("No permissions bound to this RPT")

            logger.debug("response: %s" % irep.to_json())
            response = Response(irep.to_json(), content="application/json")
        except ToOld:
            logger.info("RPT expired")
            irep = IntrospectionResponse(valid=False)
            response = Response(irep.to_json(), content="application/json")
        except KeyError:
            response = BadRequest()

        return response

    def permission_registration_endpoint_(self, entity, **kwargs):
        """
        The endpoint URI at which the resource server registers a
        client-requested permission with the authorization server.
        This is a proposed permission waiting for the user to accept it.
        """
        request = kwargs["request"]
        _ticket = rndstr(24)
        logging.debug("Registering permission request: %s" % request)
        resp = PermissionRegistrationResponse(ticket=_ticket)
        self.permit.add_request(entity, _ticket, request)

        return Created(resp.to_json(), content="application/json")

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
            assert areq["scope"] in UMA_SCOPE.values()
        except AssertionError:
            logger.error("Asked for scope which I don't deal with")
            err = TokenErrorResponse(error="invalid_scope")
            return Response(err.to_json(), content="application/json")

        return None

    def create_uma_providerinfo(self, pcr_class=ProviderConfiguration):
        kwargs = dict([(k, v) for k, v in self.conf_info.items()
                       if k in pcr_class.c_param])
        _response = pcr_class(**kwargs)

        for endp in UmaAS.endp:
            _e = endp(None)
            _response[_e.name] = "%s%s" % (self.baseurl, _e.etype)

        logger.debug("provider_info_response: %s" % (_response.to_dict(),))
        return _response

    #noinspection PyUnusedLocal
    def providerinfo_endpoint_(self, handle="", **kwargs):
        logger.debug("@providerinfo_endpoint")
        try:
            _response = self.create_uma_providerinfo()

            headers = [("Cache-Control", "no-store"), ("x-ffo", "bar")]
            #if handle:
            #    (key, timestamp) = handle
            #    if key.startswith(STR) and key.endswith(STR):
            #        cookie = self.cookie_func(key, self.cookie_name, "pinfo",
            #                                  self.sso_ttl)
            #        headers.append(cookie)

            resp = Response(_response.to_json(), content="application/json",
                            headers=headers)
        except Exception, err:
            message = traceback.format_exception(*sys.exc_info())
            logger.error(message)
            resp = Response(message, content="html/text")

        return resp

    def get_subsets(self, owner, requestor, scopes):
        res = {}
        try:
            permits = self.permit.get_permit_by_requestor(owner, requestor)
        except KeyError:
            return res

        for permit, (_scopes, time_stamp) in permits.items():
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

    def register_permission(self, owner, rpt, rsid, scopes):
        now = time.time()
        perm = AuthzDescription(resource_set_id=rsid, scopes=scopes,
                                expires_at=now + self.session.lifetime,
                                issued_at=now)

        self.permit.set_accepted(owner, rpt, perm)

    def rpt_endpoint_(self, entity, **kwargs):
        """
        Registers an Authorization Description

        :param request:
        :param requestor:
        :param client_id: The UMA client, in essence the IdP
        :return: A Response instance
        """

        adr = AuthorizationDataRequest().from_json(kwargs["request"])
        owner = self.permit.get_owner_of_request_target(adr["ticket"])

        # Get request permission that the resource server has registered
        try:
            permission = AuthzDescription().from_json(
                self.permit.get_request(owner, adr["ticket"]))
        except KeyError:
            return BadRequest()
        else:
            self.permit.del_request(owner, adr["ticket"])

        # Verify that the scopes are defined for the resource set
        _mid = self.map_rsid_id[permission["resource_set_id"]]
        rsd = self.resource_set.read(_mid)
        for scope in permission["scopes"]:
            try:
                assert scope in rsd["scopes"]
            except AssertionError:
                return BadRequest("Undefined scopes")

        # Is there any permissions registered by the owner, if so verify
        # that it allows what is requested. Return what is allowed !
        _requester = self.get_requester(entity)

        try:
            allow_scopes, timestamp = self.permit.get_permit(
                owner, _requester, permission["resource_set_id"])
        except KeyError:  #
            if "subsets" in rsd:  # complex resource set
                permissions = self.get_subsets(owner, _requester,
                                               permission["scopes"])
                for rsid, scopes in permissions.items():
                    self.register_permission(owner, adr["rpt"], rsid, scopes)
            else:
                return BadRequest("No permission given")
        else:
            _scopes = []
            for scope in permission["scopes"]:
                try:
                    assert scope in allow_scopes
                except AssertionError:
                    pass
                else:
                    _scopes.append(scope)

            # bind _requester to specific RPT for this user
            try:
                self.eid2rpt[owner][_requester] = adr["rpt"]
            except KeyError:
                self.eid2rpt[owner] = {_requester: adr["rpt"]}

            self.register_permission(owner, adr["rpt"],
                                     permission["resource_set_id"], _scopes)
        return Created("")

    def remove_permission(self, owner, requestor, resource_name):
        """
        :param owner: The resource owner
        :param requestor: The SP entity ID
        :param resource_name: The name of the resource set
        """
        obj = self.resource_set.find(name=resource_name)
        rsid = self.map_id_rsid[obj["_id"]]

        try:
            self.permit.delete_permit(owner, requestor, rsid)
        except KeyError:
            pass

        try:
            _user = "%s@%s" % (owner, requestor)
            rm_rpt = self.permit.rm_accepted(_user, rsid)
        except KeyError:
            pass
        else:
            for _rpt in rm_rpt:
                # immediate expiration
                self.session.update(_rpt, expires_at=0)

    def store_permission(self, user, requestor, rsids):
        """
        :param user: The resource owner
        :param requestor: The requestor ID
        :param rsids: dictionary with Resource set IDs as keys and scopes
            as values
        """

        logger.info("store: (%s, %s, %s)" % (user, requestor, rsids))

        present = self.permit.get_rsid_permits(user, requestor)
        _new = [k for k in rsids.keys() if k not in present]

        for rsid in _new:
            scopes = rsids[rsid]
            if scopes is None:
                rs = self.resource_set.read(self.map_rsid_id[rsid])
                scopes = rs["scopes"]
            self.permit.set_permit(user, requestor, rsid, scopes)

        _rem = [k for k in present if k not in rsids]
        for rsid in _rem:
            self.permit.delete_permit(user, requestor, rsid)

    def read_permission(self, user, requestor, name):
        obj = self.resource_set.find(name=name)
        rsid = self.map_id_rsid[obj["_id"]]
        return self.permit.get_permit(user, requestor, rsid)

    def rec_rm_permission(self, user, requestor, rsid):
        """
        If the resource set is a complex set, remove all subset permissions
        :param user: The owner of the resource
        :param requestor: Who the permission is applying to
        :param rsid: The resource set name
        """
        rs = self.resource_set.read(self.map_rsid_id[rsid])
        if "subsets" in rs:
            for ss in rs["subsets"]:
                self.rec_rm_permission(user, requestor, ss)
        try:
            self.permit.delete_permit(user, requestor, rsid)
        except KeyError:
            pass

    def rm_permission(self, user, requestor, rsid):
        """
        If the resource set is a complex set, remove all subset permissions
        :param user: The owner of the resource
        :param requestor: Who the permission is applying to
        :param rsid: The resource set name
        """
        logger.info("remove: (%s, %s, %s)" % (user, requestor, rsid))
        self.rec_rm_permission(user, requestor, rsid)
        return True

    def rsid_permits(self, user, requestor):
        return self.permit.get_rsid_permits(user, requestor)

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
        :param auth: authentication information
        """
        try:
            owner, client_id = client_authentication(self.sdb, authn)
        except AuthnFailed:
            return Unauthorized()

        return self.rpt_endpoint_(owner, client_id, **kwargs)

    def introspection_endpoint(self, request="", **kwargs):
        try:
            owner, client_id = client_authentication(self.sdb, kwargs["authn"])
        except AuthnFailed:
            return Unauthorized()
        return self.introspection_endpoint_(request, owner, **kwargs)

    def providerinfo_endpoint(self, handle="", **kwargs):
        return self.providerinfo_endpoint_(handle, **kwargs)

    def resource_set_registration_endpoint(self, path, method, body="",
                                           if_match="", **kwargs):
        try:
            owner, client_id = client_authentication(self.sdb, kwargs["authn"])
        except AuthnFailed:
            return Unauthorized()
        return self.resource_set_registration_endpoint_(path, method,
                                                        body, owner, client_id,
                                                        if_match, **kwargs)

    def dynamic_client_endpoint(self, request="", environ=None, **kwargs):
        return self.registration_endpoint(request, environ, **kwargs)

    def permission_registration_endpoint(self, request="", authn="", **kwargs):
        try:
            owner, client_id = client_authentication(self.sdb, authn)
        except AuthnFailed:
            return Unauthorized()

        return self.permission_registration_endpoint_(request, owner,
                                                      client_id=client_id,
                                                      **kwargs)

    # def authorization_data_request_endpoint(self, request="", authn="",
    #                                         **kwargs):
    #     try:
    #         owner, client_id = client_authentication(self.sdb, authn)
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
            "dyn_reg": dynreg.Provider(
                base, sdb, cdb, authn_broker, authz, client_authn,
                symkey, urlmap,
                client_authn_methods=CLIENT_AUTHN_METHOD)}

        self.endp.extend(self.srv["oidc"].endp)
        self.endp = list(set(self.endp))
        self.srv["oidc"].jwks_uri = self.jwks_uri
        self.srv["oidc"].baseurl = base

        self.request2endpoint = dict(
            [(e.__class__.__name__, "%s_endpoint" % e.etype) for e in self.endp])

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
        :param auth: authentication information
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
        return self.srv["oidc"].authorization_endpoint(request, **kwargs)

    def token_endpoint(self, request="", **kwargs):
        return self.srv["oidc"].token_endpoint(request, **kwargs)

    def client_info_endpoint(self, request, environ, method, query):
        _srv = self.srv["dyn_reg"]
        return _srv.client_info_endpoint(request, environ, method, query)

