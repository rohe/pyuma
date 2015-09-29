from uma.message import ResourceSetDescription
from uma.uma_info_provider import UMAInformationProvider

__author__ = 'roland'


class UserInfo(UMAInformationProvider):
    def __init__(self, db, base, scopes):
        UMAInformationProvider.__init__(self)
        self.db = db
        self.base = base
        self.scopes = scopes

    def __getitem__(self, item):
        return self.db[item]

    def build_resource_set_descriptions(self, user):
        """
        Will return a list of ResourceSetDescriptions covering all
        resource sets.

        :param user: Who's resources to describe
        :return: list of tuples of local id and ResourceSetDescription instances
        """
        rss = []
        for key, val in self.db[user].items():
            if isinstance(val, list):
                for v in val:
                    name = "{} {}={}".format(user, key, v)
                    _id = "{}:{}:{}".format(user, key, v)
                    rss.append((_id, ResourceSetDescription(scopes=self.scopes,
                                                            name=name)))
            else:
                name = "{} {}={}".format(user, key, val)
                _id = "{}:{}:{}".format(user, key, val)
                rss.append((_id, ResourceSetDescription(scopes=self.scopes,
                                                        name=name)))
            name = "{} {}".format(user, key)
            _id = "{}:{}".format(user, key)
            rss.append((_id, ResourceSetDescription(scopes=self.scopes,
                                                    name=name)))

        return rss
