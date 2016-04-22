import json
import logging

from oic.exception import MessageException
from oic.utils.jwt import JWT
from oic.utils.time_util import utc_time_sans_frac

from uma.authz_db import AuthzDB, PermissionDescription
from uma.authz_srv import RSR_PATH
from uma.message import AuthzDescription, ErrorResponse
from uma.permission import Permission
from uma.permission_request import PermissionRequests
from uma.rsdb import MemResourceSetDB, UnknownObject

__author__ = 'roland'

logger = logging.getLogger(__name__)


class ADB(object):
    """ Expects to be one ADB instance per Resource Server """

    def __init__(self, keyjar, rpt_lifetime, iss, ressrv_id):
        # database with all the registered resource sets
        self.resource_set = MemResourceSetDB()
        # database with all permission requests
        self.permission_requests = PermissionRequests()
        # database with all authorization decisions
        self.authz_db = AuthzDB()
        # database with all registered permissions
        self.permit = Permission()

        self.map_rsid_id = {}
        self.map_id_rsid = {}
        self.map_user_id = {}

        self.rpt_factory = JWT(keyjar, lifetime=rpt_lifetime, iss=iss)
        self.authzdesc_lifetime = 3600
        self.client_id = ressrv_id

    def pending_permission_requests(self, owner, user):
        """
        Return outstanding permission requests that is known to belong to
        an owner and bound to a requestor.

        :param owner:
        :param user:
        :return:
        """
        res = []
        for tick in self.permission_requests.requestor2tickets(user):
            rsid = self.permission_requests.ticket2rsid(tick)
            if self.resource_set.belongs_to(rsid, owner):
                res.append(tick)
        return res

    def permission_request_allowed(self, ticket, requestor):
        """
        Verify that whatever permission requests the ticket represents
        they are now allow.

        :param ticket: The ticket
        :param requestor: Who has the ticket
        :return: True/False
        """
        try:
            prrs = self.permission_requests[ticket]
        except KeyError:
            logger.warning("Someone is using a ticket that doesn't exist")
            return False
        else:
            for prr in prrs:
                owner = self.resource_set.owner(prr['resource_set_id'])
                if not self.authz_db.match(owner, requestor, **prr.to_dict()):
                    return False
            return True

    def store_permission(self, permission, owner, user):
        """

        """
        max_scopes = self.resource_set.read(
            owner, permission['resource_set_id'])["scopes"]

        # if no scopes are defined == all are requested
        try:
            _scopes = permission['scopes']
        except KeyError:
            scopes = max_scopes
        else:
            scopes = [s for s in _scopes if s in max_scopes]

        pm = PermissionDescription(
            resource_set_id=permission['resource_set_id'], scoped=scopes,
            entity=user)
        self.authz_db.add(owner, requestor=user, perm_desc=pm)

    def register_permission(self, owner, rpt, rsid, scopes, requires=None):
        """

        :param owner: Resource owner
        :param rpt: Requesting party token
        :param rsid: Resource set id
        :param scopes: list of scopes
        :param requires: Other requirements
        """

        now = utc_time_sans_frac()
        authz = AuthzDescription(resource_set_id=rsid, scopes=scopes,
                                 exp=now + self.authzdesc_lifetime,
                                 iat=now)

        self.permit.set(owner, rpt, authz, requires)

    def resource_set_registration(self, method, owner, body, rsid):
        """

        :param method:
        :param owner:
        :param body:
        :param rsid:
        :return:
        """
        if method == "POST":  # create
            args = {"oid": owner, "data": body}
            func = self.resource_set.create
        elif method == "PUT":  # update
            args = {
                "oid": owner, "data": body, "rsid": rsid,
                # "if_match": if_match
            }
            func = self.resource_set.update
        elif method == "GET":
            args = {"oid": owner}
            if not rsid:  # List
                func = self.resource_set.list
            else:  # Read
                func = self.resource_set.read
                args["rsid"] = rsid
        elif method == "DELETE":
            args = {"rsid": rsid, "oid": owner}
            func = self.resource_set.delete
        else:
            return {400: {'message': "Message error"}}

        logger.debug("operation: %s" % func)
        logger.debug("operation args: %s" % (args,))
        try:
            body = func(**args)
        except MessageException as err:
            response = {
                400: {
                    'message': ErrorResponse(
                        error="invalid_request",
                        error_description=str(err)).to_json(),
                    'content': "application/json"}}
        except UnknownObject:
            response = {
                404: {
                    'message': ErrorResponse(error="not_found").to_json(),
                    'content': "application/json"}}
        else:
            response = None
            if isinstance(body, ErrorResponse):
                pass
            else:
                if func == self.resource_set.delete:
                    # As a side effect all permissions assigned that references
                    # this resource set should be deleted
                    self.resource_set.delete(owner, rsid)
                    response = {204: None}
                elif func == self.resource_set.create:
                    _etag = self.resource_set.etag[body["_id"]]
                    response = {
                        201: {
                            'message': body.to_json(),
                            'content': "application/json",
                            'headers': [
                                ("ETag", _etag),
                                ("Location", "/{}/{}".format(RSR_PATH,
                                                             body["_id"]))]
                        }}
                elif func == self.resource_set.update:
                    _etag = self.resource_set.etag[body["_id"]]
                    response = {204: {'content': "application/json",
                                      'headers': [("ETag", _etag)]}}
                elif func == self.resource_set.list:
                    response = {200: {'message': json.dumps(body)}}

            if not response:
                response = {200: {'message': body.to_json(),
                                  'content': "application/json"}}
        return response

    def issue_rpt(self, ticket, requestor):
        """
        As a side effect if a RPT is issued the ticket is removed and
        can not be used again.

        """
        if not self.permission_request_allowed(ticket, requestor):
            return None

        rpt = self.rpt_factory.pack(aud=[self.client_id], type='rpt')

        for rsd in self.permission_requests[ticket]:
            owner = self.resource_set.owner(rsd['resource_set_id'])
            self.permit.bind_owner_to_rpt(owner, rpt)

            self.register_permission(owner, rpt, rsd['resource_set_id'],
                                     rsd['scopes'])

        del self.permission_requests[ticket]
        return rpt

    def introspection(self, rpt):
        try:
            res = []
            for owner in self.permit.rpt2owner[rpt]:
                res.extend(self.permit.get(owner, rpt))
            return res
        except KeyError:
            return None
