import logging

from oic.utils.jwt import JWT
from oic.utils.time_util import utc_time_sans_frac

from uma.authz_db import AuthzDB
from uma.authz_db import PermissionDescription
from uma.message import AuthzDescription
from uma.permission import Permission
from uma.permission_request import PermissionRequests
from uma.rsdb import MemResourceSetDB

__author__ = 'roland'

logger = logging.getLogger(__name__)


class TicketError(Exception):
    def __init__(self, typ, reason=''):
        self.typ = typ
        self.reason = reason

    def __str__(self):
        return '{}:{}'.format(self.typ, self.reason)


class ADB(object):
    """ Expects to be one ADB instance per Resource Server """

    def __init__(self, keyjar, rpt_lifetime, iss, ressrv_id, rsr_path,
                 ticket_lifetime=3600):
        # database with all permission requests
        self.permission_requests = PermissionRequests()
        # database with all authorization decisions
        self.authz_db = AuthzDB()
        # database with all registered permissions
        self.permit = Permission()
        # database with all the registered resource sets
        self.resource_set = MemResourceSetDB(
            rsr_path=rsr_path, delete_rsid=self.permit.delete_rsid)

        self.map_rsid_id = {}
        self.map_id_rsid = {}
        self.map_user_id = {}

        self.rpt_factory = JWT(keyjar, lifetime=rpt_lifetime, iss=iss)
        self.ticket_factory = JWT(keyjar, lifetime=ticket_lifetime, iss=iss)
        self.authzdesc_lifetime = 3600
        self.client_id = ressrv_id
        self.rsr_path = rsr_path
        self.ad2rpt = {}
        self.rpt2adid = {}

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

    def is_expired(self, tinfo):
        if utc_time_sans_frac() <= tinfo['exp']:
            return False
        return True

    def permission_request_allowed(self, ticket, identity):
        """
        Verify that whatever permission requests the ticket represents
        they are now allow.

        :param ticket: The ticket
        :param identity: Who has the ticket
        :return: Dictionary, with permission request as key and
            identifiers of authz decisions that permits the requests as values.
        """

        _tinfo = self.rpt_factory.unpack(ticket)
        if self.is_expired(_tinfo):
            raise TicketError('expired',
                              '{} > {}'.format(utc_time_sans_frac(),
                                               _tinfo['exp']))

        try:
            prrs = self.permission_requests[ticket]
        except KeyError:
            logger.warning("Someone is using a ticket that doesn't exist")
            raise TicketError('invalid', ticket)
        else:
            result = {}
            for prr in prrs:
                owner = self.resource_set.owner(prr['resource_set_id'])
                _adids = self.authz_db.match(owner, identity, **prr.to_dict())
                if not _adids:
                    # all or nothing
                    raise TicketError('not_authorized')
                result[prr.to_json()] = _adids
            return result

    def store_permission(self, permission, owner):
        """
        Store a permission

        :param permission: The permission to store
        :param owner: The user setting the permission
        :return: A permission ID
        """
        max_scopes = self.resource_set.read(
            owner, permission['resource_set_id'])["scopes"]

        # if no scopes are defined == all are requested
        try:
            _scopes = permission['scopes']
        except KeyError:
            permission['scopes'] = max_scopes
        else:
            permission['scopes'] = [s for s in _scopes if s in max_scopes]

        pm = PermissionDescription(**permission)
        return self.authz_db.add(owner, perm_desc=pm)

    def register_permission(self, owner, rpt, rsid, scopes):
        """

        :param owner: Resource owner
        :param rpt: Requesting party token
        :param rsid: Resource set id
        :param scopes: list of scopes
        """

        now = utc_time_sans_frac()
        authz = AuthzDescription(resource_set_id=rsid, scopes=scopes,
                                 exp=now + self.authzdesc_lifetime,
                                 iat=now)

        self.permit.set(owner, rpt, authz)

    def resource_set_registration(self, method, owner, body=None, rsid=''):
        """

        :param method: HTTP method
        :param owner: The owner of the resource set
        :param body: description of the resource set
        :param rsid: resource set id
        :return: tuple (http response code, http message, http response args)
        """

        return self.resource_set.registration(method, owner, body, rsid)

    def issue_rpt(self, ticket, identity):
        """
        As a side effect if a RPT is issued the ticket is removed and
        can not be used again.

        :param ticket: The ticket
        :param identity: Information about the entity who wants the RPT
        :return: A RPT
        """
        idmap = self.permission_request_allowed(ticket, identity)
        if not idmap:
            return None

        rpt = self.rpt_factory.pack(aud=[self.client_id], type='rpt')

        for rsd in self.permission_requests[ticket]:
            owner = self.resource_set.owner(rsd['resource_set_id'])
            self.permit.bind_owner_to_rpt(owner, rpt)
            self.bind_rpt_to_authz_dec(rpt, idmap[rsd.to_json()])
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
            return []

    def bind_rpt_to_authz_dec(self, rpt, adid):
        for id in adid:
            try:
                self.ad2rpt[id].append(rpt)
            except KeyError:
                self.ad2rpt[id] = [rpt]

        try:
            self.rpt2adid[rpt].extend(adid)
        except KeyError:
            self.rpt2adid[rpt] = adid

    def remove_permission(self, owner, pid):
        """
        :param owner: The owner of the resource set
        :param pid: The permission id
        """
        # find all RPTs that has been issued based on this permission
        for rpt in self.ad2rpt[pid]:
            if self.rpt2adid[rpt] == [pid]:
                del self.rpt2adid[rpt]
            else:
                self.rpt2adid[rpt].remove(pid)
            self.permit.delete_rpt(rpt)

        del self.ad2rpt[pid]

        self.authz_db.delete(owner, pid=pid)

    def read_permission(self, owner, pid):
        return self.authz_db.read(owner, pid)
