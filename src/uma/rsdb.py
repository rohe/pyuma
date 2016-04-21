import hashlib
import json
import uuid

from uma.message import ResourceSetResponse
from uma.message import StatusResponse

__author__ = 'rolandh'

RSR = [k for k in list(ResourceSetResponse.c_param.keys())
       if not k.startswith("_")]


class UnknownObject(Exception):
    pass


class ResourceSetDB(object):
    def __init__(self, **kwargs):
        self.db = None
        self.rsid2oid = {}

    def create(self, data, oid):
        raise NotImplemented()

    def read(self, oid, rsid):
        raise NotImplemented()

    def update(self, data, oid, rsid):
        raise NotImplemented()

    def delete(self, oid, rsid):
        raise NotImplemented()

    def list(self, oid):
        raise NotImplemented()


class MemResourceSetDB(ResourceSetDB):
    def __init__(self, **kwargs):
        ResourceSetDB.__init__(self, **kwargs)
        self.db = {}
        self.etag = {}

    def create(self, data, oid):
        rset = ResourceSetResponse().deserialize(data, "json")
        rset.weed()

        m = hashlib.md5(rset.to_json().encode("utf8"))
        rsid = m.hexdigest()
        rset["_id"] = rsid
        # Need to add _id before verifying
        rset.verify()

        try:
            self.db[oid][rsid] = rset
        except KeyError:
            self.db[oid] = {rsid: rset}

        # backward lookup table
        self.rsid2oid[rsid] = oid

        # add a revision number
        self.etag[rsid] = str(uuid.uuid4())
        status = StatusResponse(_id=rsid)
        return status

    def read(self, oid, rsid):
        try:
            rset = self.db[oid][rsid]
        except KeyError:
            raise UnknownObject()

        return rset

    def update(self, data, oid, rsid):
        try:
            _ = self.db[oid][rsid]
        except KeyError:
            raise UnknownObject()

        _dat = json.loads(data)
        _d = dict([(c, v) for c, v in list(_dat.items())
                   if c in RSR and c != "_id"])

        _new = ResourceSetResponse(**_d)
        _new["_id"] = rsid
        _new.verify()

        if _new:
            self.db[oid][rsid] = _new
            # new revision
            self.etag[rsid] = str(uuid.uuid4())
            status = StatusResponse(_id=rsid)
        else:
            status = StatusResponse(_id=rsid)

        return status

    def delete(self, oid, rsid):
        try:
            del self.db[oid][rsid]
        except KeyError:
            raise UnknownObject()

    def list(self, oid):
        return list(self.db[oid].keys())

    def belongs_to(self, rsid, owner):
        return rsid in self.db[owner]
