from ldap3 import ALL_ATTRIBUTES
from ldap3.core.connection import Connection


class LDAPDBWrap(object):
    """ Wrapper to make an LDAP database look like a dict.
    Returns all info about a user as a dictionary.
    """

    def __init__(self, uri="localhost", base="dc=localhost", filter_pattern="uid={}"):
        self.uri = uri
        self.base = base
        self.filter_pattern = filter_pattern

    def __getitem__(self, user):
        with Connection(self.uri, auto_bind=True) as conn:
            conn.search(self.base, '({})'.format(self.filter_pattern.format(user)),
                        attributes=ALL_ATTRIBUTES)

        entry = conn.entries[0]
        return entry.entry_get_attributes_dict()
