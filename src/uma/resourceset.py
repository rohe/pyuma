from uma.message import ResourceSetResponse
from uma.message import ResourceSetDescription
from uma.message import StatusResponse
from src.uma.authzsrv import RSR_PATH

__author__ = 'roland'


class ResourceSetHandler(object):
    def __init__(self, dataset, client, resource_owner):
        self.dataset = dataset
        self.client = client
        self.rsd_map = {}
        self.rsid2lid = {}
        self.resource_owner = resource_owner
        self.token = {}

    def _url(self, rsid=""):
        if rsid:
            return "{}/resource_set/{}".format(
                self.client.provider_info["resource_set_registration_endpoint"],
                rsid)
        else:
            return "{}/resource_set".format(
                self.client.provider_info["resource_set_registration_endpoint"])

    def com_args(self, request, method, request_args, extra_args, http_args,
                 rsid,
                 **kwargs):

        endpoint = self._url(rsid)

        url, body, ht_args, csi = self.client.request_info(request, method,
                                                           request_args,
                                                           extra_args,
                                                           endpoint=endpoint,
                                                           **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        return {"url": url, "body": body, "http_args": http_args, "csi": csi}

    def read_resource_set_description(self, request=ResourceSetDescription,
                                      body_type="", method="GET",
                                      request_args=None, extra_args=None,
                                      http_args=None, rsid="",
                                      response_cls=ResourceSetResponse,
                                      **kwargs):
        """
        Reads a resource set description from the Authorization server

        :returns: A ResourceSetDescription instance
        """

        _kwargs = self.com_args(request, method, request_args,
                                extra_args, http_args, rsid, **kwargs)

        return self.client.request_and_return(response_cls, method, body_type,
                                              **_kwargs)

    def delete_resource_set_description(self, rsid):
        """
        Removes a resource set description from the Authorization server

        :param rsid:
        :returns: True if successful
        """

        resp = self.client.http_request(self._url(rsid), "DELETE")

        return True

    def update_resource_set_description(self, request=ResourceSetDescription,
                                        body_type="json", method="PUT",
                                        request_args=None, extra_args=None,
                                        http_args=None, rsid="",
                                        response_cls=ResourceSetResponse,
                                        **kwargs):
        """
        Updates a resource set description from the Authorization server

        :param rsid:
        :returns: True if successful
        """

        _kwargs = self.com_args(request, method, request_args,
                                extra_args, http_args, rsid, **kwargs)

        return self.client.request_and_return(response_cls, method, body_type,
                                              **_kwargs)

    def list_resource_set_description(self):
        """
        List resource set descriptions on an Authorization server

        :param rsid:
        :returns: List of ResourceSetDescription instance
        """

        resp = self.client.http_request(self._url(), "GET")
        return []

    def is_resource_set_changed(self, rsid, val):
        pass

    def create_resource_set_description(self, request=ResourceSetDescription,
                                        body_type="json", method="POST",
                                        request_args=None, extra_args=None,
                                        http_args=None,
                                        response_cls=ResourceSetResponse,
                                        **kwargs):

        _kwargs = self.com_args(request, method, request_args,
                                extra_args, http_args, **kwargs)

        return self.client.request_and_return(response_cls, method, body_type,
                                              **_kwargs)

    def register_resource_set_description(self, info_filter=None):
        if info_filter is None:
            info_filter = {"user": self.resource_owner}
        else:
            info_filter.update({"user": self.resource_owner})

        res_set_desc = self.dataset.build_resource_set_descriptions(info_filter)

        request_args = {"access_token": self.token["PAT"]}
        ht_args = self.client.client_authn_method[
            "bearer_header"](self).construct({}, request_args=request_args)

        authn = ht_args["headers"]["Authorization"]

        ro_map = self.rsd_map[self.resource_owner]
        for lid, _desc in res_set_desc:
            res = self.create_resource_set_description(authn=authn,
                                                       request_args=_desc)
            sr = StatusResponse().from_json(res.message)
            assert res.status == "201 Created"

            # The resource server should keep a map between resource and AS (
            # _rev,_id)
            rsid = sr['_id']
            ro_map[lid] = {'_id': rsid, 'resource_set_desc': _desc}
            self.rsid2lid[rsid] = lid

    def get_info(self, *args):
        return self.dataset.get(*args)

    def query2permission_registration_request_primer(self, operation, path,
                                                     query):
        return self.dataset.query2permission_registration_request_primer(
            operation, path, query)
