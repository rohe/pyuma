from uma.dbwrap import DBWrap
from uma.message import ResourceSetDescription

__author__ = 'roland'

# -----------------------------------------------------------------------------

def _local_id(*args):
    return ":".join(args)


class DictDBWrap(DBWrap):
    def _register(self, prim, key, val=None, scopes=None, parent=None):
        if val:
            name = "{} {}={}".format(prim, key, val)
            _id = _local_id(prim, key, val)
        else:
            name = "{} {}".format(prim, key)
            _id = _local_id(prim, key)

        if scopes is None:
            scopes = list(self.scopes2op.keys())

        _rsd = ResourceSetDescription(scopes=scopes, name=name)
        if parent is not None:
            self.lid2scopes[_id] = scopes
            try:
                self.child_lid[parent].append(_id)
            except KeyError:
                self.child_lid[parent] = [_id]
        return {_id: _rsd}

    def _resource_set_descriptions(self, prim, sec=None, scopes=None):
        try:
            ava = self.db[prim]
        except KeyError:
            return {}

        rsd = {}
        for key, val in ava.items():
            if sec and key not in sec:
                continue  # skip this attribute

            _parent_rsd = self._register(prim, key, scopes=scopes)
            _parent = list(_parent_rsd.keys())[0]
            if isinstance(val, list):
                for v in val:
                    rsd.update(self._register(prim, key, v, scopes, _parent))
            else:
                rsd.update(self._register(prim, key, val, scopes, _parent))

        return rsd

    def build_resource_set_descriptions(self, prim, sec=None, scopes=None):
        """
        Will return a list of ResourceSetDescriptions covering all
        resource sets belonging to a controller.

        :param prim: Primary key
        :param sec: Secondary keys
        :param scopes: Which scopes to use for these resources.
        :return: list of 2-tuples (local_id, ResourceSetDescription instance)
        """

        rsd = self._resource_set_descriptions(prim, sec, scopes)
        self.rsd_set[(prim, sec)] = rsd
        return rsd

    def update_resource_set_description(self, prim, sec=None, scopes=None):
        """
        :param prim: The owner of the resource sets
        :return: A dictionary with keys ["add", "update", "delete"] and
            values necessary modifications of the ASs view.
        """
        res = {"delete": [], "add": {}, "update":{}}
        rsd = self._resource_set_descriptions(prim, sec, scopes)
        orig_rsd = self.rsd_set[(prim, sec)]
        del_key = []
        for key, val in orig_rsd.items():
            try:
                new_val = rsd[key]
            except KeyError:
                res["delete"].append(key)
                del_key.append(key)
            else:
                if new_val == val:
                    continue
                else:
                    res["update"].update({key: new_val})

        for key in del_key:
            del orig_rsd[key]
            del self.lid2scopes[key]

        for key, val in rsd.items():
            if key not in orig_rsd:
                res['add'].update({key: val})

        if orig_rsd == {}:
            del self.rsd_set[(prim, sec)]
        else:
            self.rsd_set[(prim, sec)] = orig_rsd

        return res

    def resource_name(self, path):
        """
        """
        return path

    @staticmethod
    def get_necessary_scope(environ):
        return

    def get(self, key, *args):
        """
        Works for hierarchical data, dictionaries of dictionaries.
        Turtles all the way down.

        """
        _info = self.db[key]
        for arg in args:
            _info = _info[arg]

        return _info

    def add(self, key, ava):
        self.db[key] = ava

    def delete(self, key):
        del self.db[key]

    def update(self, key, ava):
        try:
            self.db[key].update(ava)
        except KeyError:
            self.db[key] = ava

    def query2permission_registration_request_primer(self, ro, scope, attrs):
        res = []
        for attr in attrs:
            for l in self.child_lid[_local_id(ro, attr)]:
                if scope in self.lid2scopes[l]:
                    res.append((l, scope))
        return res
