from oic.utils.time_util import utc_time_sans_frac
from uma.message import AuthzDescription

__author__ = 'roland'


class Permission(object):
    """
    Stores all registered permissions
    """
    def __init__(self):
        self.db = {}
        self.owner2rpt = {}
        self.rpt2owner = {}

    def init_owner(self, owner):
        self.db[owner] = {}

    def set(self, owner, rpt, authz_desc, require=None):
        """
        Note there can be more then one authz_desc per owner-rpt pair

        :param owner: The owner of the resource
        :param rpt: A key to store the description under
        :param authz_desc: The Authz description
        :param require: Whatever else is necessary to use this authz.
        :return:
        """
        if owner not in self.db:
            self.init_owner(owner)

        _val = {"desc": authz_desc, "req": require}
        try:
            self.db[owner][rpt].append(_val)
        except KeyError:
            self.db[owner] = {rpt: [_val]}

    def get(self, owner, rpt):
        return self.db[owner][rpt]

    def keys(self, owner):
        return list(self.db[owner].keys())

    def delete(self, owner, rsid):
        _remove = []
        for rpt, desc in list(self.db[owner].items()):
            if desc["resource_set_id"] == rsid:
                _remove.append(rpt)

        for rpt in _remove:
            del self.db[owner][rpt]

        return _remove

    @staticmethod
    def construct_authz_desc(rsid, scopes, lifetime=3600):
        now = utc_time_sans_frac()
        return AuthzDescription(resource_set_id=rsid, scopes=scopes,
                                exp=now + lifetime, iat=now)

    def bind_owner_to_rpt(self, owner, rpt):
        try:
            if owner not in self.rpt2owner[rpt]:
                self.rpt2owner[rpt].append(owner)
        except KeyError:
            self.rpt2owner[rpt] = [owner]

        try:
            if rpt not in self.owner2rpt[owner]:
                self.owner2rpt[owner].append(rpt)
        except KeyError:
            self.owner2rpt[owner] = [rpt]
