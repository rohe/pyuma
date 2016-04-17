from oic.utils.time_util import utc_time_sans_frac
from uma.message import AuthzDescription

__author__ = 'roland'


class Permission(object):
    """
    Stores all registered permissions
    """
    def __init__(self):
        self.db = {}

    def init_owner(self, owner):
        self.db[owner] = {}

    def set_request(self, owner, requestor, resource_id, scopes=None):

        if owner not in self.db:
            self.init_owner(owner)

        _perm = self.db[owner]["pending"]

        _val = {"scopes": scopes, "iat": utc_time_sans_frac()}

        try:
            _perm[requestor][resource_id] = _val
        except KeyError:
            try:
                _perm[requestor] = {resource_id: _val}
            except KeyError:
                self.db[owner]["pending"] = {requestor: {resource_id: _val}}

    def get_request(self, owner, requestor, resource_id):
        """
        :return: A dict with keys ['scopes', 'iat', 'require']
        """
        return self.db[owner]["pending"][requestor][resource_id]

    def get_request_by_requestor(self, owner, requestor):
        """
        :return: A dictionary with resource_id as keys and dicts as values
        """
        return self.db[owner]["pending"][requestor]

    def delete_request(self, owner, requestor, resource_id):
        try:
            del self.db[owner]["pending"][requestor][resource_id]
        except KeyError:
            pass

    def delete_request_by_resource_id(self, owner, resource_id):
        try:
            _perm = self.db[owner]["pending"]
        except KeyError:
            pass
        else:
            for req, spec in list(_perm.items()):
                if resource_id in spec:
                    self.delete_request(owner, req, resource_id)

                if _perm[req] == {}:
                    del self.db[owner]['pending'][req]

    def get_requests(self, owner):
        """
        :param owner: The owner of the resource
        :return: A dictionary with requestors as keys and permissions as keys
        """
        return self.db[owner]["pending"]

    def set_accepted(self, owner, rpt, authz_desc, require=None):
        if owner not in self.db:
            self.init_owner(owner)

        _val = {"desc": authz_desc, "req": require}
        try:
            self.db[owner]["accepted"][rpt].append(_val)
        except KeyError:
            self.db[owner]["accepted"] = {rpt: [_val]}

    def get_accepted_by_rpt(self, owner, rpt):
        return self.db[owner]["accepted"][rpt]

    def get_accepted(self, owner):
        return self.db[owner]["accepted"]

    def rm_accepted(self, owner, rsid):
        _remove = []
        for rpt, desc in list(self.db[owner]["accepted"].items()):
            if desc["resource_set_id"] == rsid:
                _remove.append(rpt)

        for rpt in _remove:
            del self.db[owner]["accepted"][rpt]

        return _remove

    def pending_permission_requests(self, owner, requestor):
        """
        :return: list of resource set ids
        """
        try:
            return list(self.db[owner]["pending"][requestor].keys())
        except KeyError:
            return []

    @staticmethod
    def construct_authz_desc(rsid, scopes, lifetime=3600):
        now = utc_time_sans_frac()
        return AuthzDescription(resource_set_id=rsid, scopes=scopes,
                                exp=now + lifetime, iat=now)
