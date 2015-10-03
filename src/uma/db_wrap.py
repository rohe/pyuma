__author__ = 'roland'


class DBWrap(object):
    def __init__(self, db, scopes, **kwargs):
        self.db = db
        self.scopes = scopes
        self.lid2scopes = {}
        self.child_lid = {}

    def build_resource_set_descriptions(self, filter, scopes=None):
        """
        Will return a list of ResourceSetDescriptions covering all
        resource sets belonging to a controller.

        :param filter: Which resources to target
        :param scopes: Which scopes to use for these resources.
        :return: list of 2-tuples (local_id, ResourceSetDescription instance)
        """
        rsd = []

        return rsd

    def update_resource_set_description(self, user):
        """
        :param user: The owner of the resource sets
        :return: A list of 2-tuples (changetype, change)
            changetype = ["add", "update", "delete"]
        """
        pass

    def resource_name(self, path):
        """
        """
        return path

    @staticmethod
    def get_necessary_scope(environ):
        return