__author__ = 'roland'


class DBWrap(object):
    def __init__(self, db, **kwargs):
        self.db = db
        self.scopes2op = {}
        self.lid2scopes = {}
        self.child_lid = {}
        self.rsd = []
        self.rsd_set = {}

    def build_resource_set_descriptions(self, *args):
        """
        Will return a list of ResourceSetDescriptions covering all
        resource sets belonging to a controller.

        :return: list of 2-tuples (local_id, ResourceSetDescription instance)
        """
        raise NotImplemented()

    def update_resource_set_description(self, *args):
        """
        :return: A dictionary with keys ["add", "update", "delete"] and
            values being lists of necessary modification of the ASs view.
        """
        raise NotImplemented()

    def resource_name(self, path):
        """
        """
        raise NotImplemented()

    @staticmethod
    def get_necessary_scope(environ):
        raise NotImplemented()

    # The following 4 methods represents the operations that can be
    # performed on the database. Each of these must be mapped into a scope
    def get(self, key, *args):
        raise NotImplemented()

    def add(self, key, ava):
        raise NotImplemented()

    def delete(self, key):
        raise NotImplemented()

    def update(self, key, ava):
        raise NotImplemented()

    def query2permission_registration_request_primer(self, *args):
        raise NotImplemented()

    def register_scope(self, scope, op):
        self.scopes2op[scope] = getattr(self, op)