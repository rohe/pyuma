from oic.utils.time_util import utc_time_sans_frac

__author__ = 'roland'


class UMAInformationProvider(object):
    def __init__(self, **kwargs):
        pass

    def build_resource_set_description(self, user):
        """
        Will return a list of ResourceSetDescriptions covering all
        resource sets belonging to the user.

        :param user: Who's resources to describe
        :return: list of 2-tuples (path, ResourceSetDescription instance)
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

    @staticmethod
    def filter_by_permission(authz, scope):
        """
        :param authz: An IntrospectionResponse instance
        :param scope: The scope that access is asked for
        """
        now = utc_time_sans_frac()
        try:
            assert now < authz["expires_at"]
        except KeyError:
            pass
        except AssertionError:
            return False

        for perm in authz["permissions"]:
            try:
                assert now < perm["expires_at"]
            except KeyError:
                pass
            except AssertionError:
                return False

            try:
                assert scope in perm["scopes"]
            except AssertionError:
                pass
            else:
                return True

        return False

    def resource_name(self, path):
        """
        """
        return path

    @staticmethod
    def get_necessary_scope(environ):
        return