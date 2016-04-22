from oic.utils.time_util import utc_time_sans_frac
from uma.message import AuthzDescription

__author__ = 'roland'


class Permission(object):
    """
    Stores all registered permissions
    """
    def __init__(self):
        self.db = {}
        self.rpt2owner = {}

    def init_owner(self, owner):
        self.db[owner] = {}

    def set(self, owner, rpt, authz_desc):
        """
        Note there can be more then one authz_desc per owner-rpt pair

        :param owner: The owner of the resource
        :param rpt: A key to store the description under
        :param authz_desc: The Authz description
        :return:
        """
        if owner not in self.db:
            self.init_owner(owner)

        _val = authz_desc
        try:
            self.rpt2owner[rpt].add(owner)
        except KeyError:
            self.rpt2owner[rpt] = {owner}
        try:
            self.db[owner][rpt].append(_val)
        except KeyError:
            self.db[owner][rpt] = [_val]

    def get(self, owner, rpt):
        return self.db[owner][rpt]

    def keys(self, owner):
        return list(self.db[owner].keys())

    def delete_rsid(self, owner, rsid):
        _remove = []
        try:
            items = self.db[owner].items()
        except KeyError:
            pass
        else:
            for rpt, descs in items:
                for desc in descs:
                    if desc["resource_set_id"] == rsid:
                        _remove.append(rpt)

        for rpt in _remove:
            self.delete_rpt(rpt)

        return _remove

    def delete_rpt(self, rpt):
        #self.owner2rpt[owner].remove(rpt)
        for owner in self.rpt2owner[rpt]:
            del self.db[owner][rpt]
        del self.rpt2owner[rpt]

    @staticmethod
    def construct_authz_desc(rsid, scopes, lifetime=3600):
        now = utc_time_sans_frac()
        return AuthzDescription(resource_set_id=rsid, scopes=scopes,
                                exp=now + lifetime, iat=now)

    def bind_owner_to_rpt(self, owner, rpt):
        try:
            self.rpt2owner[rpt].add(owner)
        except KeyError:
            self.rpt2owner[rpt] = {owner}
