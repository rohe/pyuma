import hashlib
import json
import logging
import uuid
from oic.exception import MessageException

from uma.message import ResourceSetResponse, ErrorResponse
from uma.message import StatusResponse

__author__ = 'rolandh'

logger = logging.getLogger(__name__)

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
    def __init__(self, rsr_path, delete_rsid, **kwargs):
        ResourceSetDB.__init__(self, **kwargs)
        self.db = {}
        self.etag = {}
        self.rsr_path = rsr_path
        self.delete_rsid = delete_rsid

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

    def owner(self, rsid):
        return self.rsid2oid[rsid]

    def registration(self, method, owner, body=None, rsid=''):
        """

        :param method: HTTP method
        :param owner: The owner of the resource set
        :param body: description of the resource set
        :param rsid: resource set id
        :return: tuple (http response code, http message, http response args)
        """
        if method == "POST":  # create
            args = {"oid": owner, "data": body}
            func = self.create
        elif method == "PUT":  # update
            args = {
                "oid": owner, "data": body, "rsid": rsid,
                # "if_match": if_match
            }
            func = self.update
        elif method == "GET":
            args = {"oid": owner}
            if not rsid:  # List
                func = self.list
            else:  # Read
                func = self.read
                args["rsid"] = rsid
        elif method == "DELETE":
            args = {"rsid": rsid, "oid": owner}
            func = self.delete
        else:
            return 400, {'message': "Message error"}

        logger.debug("operation: %s" % func)
        logger.debug("operation args: %s" % (args,))
        try:
            comres = func(**args)
        except MessageException as err:
            response = (
                400,
                ErrorResponse(error="invalid_request",
                              error_description=str(err)).to_json(),
                {'content': "application/json"})
        except UnknownObject:
            response = (
                404,
                ErrorResponse(error="not_found").to_json(),
                {'content': "application/json"})
        else:
            response = None
            if isinstance(comres, ErrorResponse):
                pass
            else:
                if func == self.delete:
                    # As a side effect all permissions assigned that references
                    # this resource set should be deleted
                    self.delete_rsid(owner, rsid)
                    response = (204, [], {})
                elif func == self.create:
                    _etag = self.etag[comres["_id"]]
                    response = (
                        201,
                        comres.to_json(),
                        {
                            'content': "application/json",
                            'headers': [
                                ("ETag", _etag),
                                ("Location", "/{}/{}".format(self.rsr_path,
                                                             comres["_id"]))]})
                elif func == self.update:
                    _etag = self.etag[comres["_id"]]
                    response = (200, comres.to_json(),
                                {'headers': [("ETag", _etag)]})
                elif func == self.list:
                    response = (200, json.dumps(comres),
                                {'content': "application/json"})

            if not response:
                response = (200,
                            comres.to_json(),
                            {'content': "application/json"})
        return response
