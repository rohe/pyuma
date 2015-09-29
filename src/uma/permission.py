from oic.utils.time_util import utc_time_sans_frac
from uma.message import PermissionRegistrationRequest

__author__ = 'roland'


class Permission(object):
    def __init__(self):
        self.db = {}
        self.request = {}

    def init_owner(self, owner):
        self.db[owner] = {
            "permit": {},
            "accepted": {},
            "permitted_at": {}
        }

    def add_request(self, ticket, req):
        """
        :param req: The Permission Registration Request as a string
        """
        self.request[ticket] = PermissionRegistrationRequest().from_json(req)

    def get_request(self, ticket):
        """
        :param ticket: The ticket returned when the Permission Registration
            Request was made
        :return: A umu.message.PermissionRegistrationRequest instance
        """
        return self.request[ticket]

    def get_outstanding_requests(self, resource_set_id):
        """
        :param resource_set_id:
        :return: A dictionary of tickets and requests
        """
        res = {}
        for _tick, req in self.request.items():
            if resource_set_id == req['resource_set_id']:
                res[_tick] = req
        return res

    def del_request(self, ticket):
        """
        Remove a specific permission request
        :param ticket: The ticket returned when the request was registered
        """
        del self.request[ticket]

    def set_permit(self, owner, requestor, resource_id, scopes=None):
        if owner not in self.db:
            self.init_owner(owner)

        _perm = self.db[owner]["permit"]

        _val = (scopes, utc_time_sans_frac())
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
        try:
            del self.db[owner]["permit"][requestor][resource_id]
        except KeyError:
            pass

    def delete_permit_by_resource_id(self, owner, resource_id):
        try:
            _perm = self.db[owner]["permit"]
        except KeyError:
            pass
        else:
            for req, spec in list(_perm.items()):
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
        for rpt, desc in list(self.db[owner]["accepted"].items()):
            if desc["resource_set_id"] == rsid:
                _remove.append(rpt)

        for rpt in _remove:
            del self.db[owner]["accepted"][rpt]

        return _remove

    def get_resource_set_id_from_request(self, ticket):
        try:
            return self.request[ticket]["resource_set_id"]
        except KeyError:
            return None

    def get_rsid_permits(self, owner, requestor):
        """
        :return: list of resource set ids
        """
        try:
            return list(self.db[owner]["permit"][requestor].keys())
        except KeyError:
            return []
