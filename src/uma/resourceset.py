import logging
from urllib.parse import parse_qs
from oic.oauth2 import SUCCESSFUL
from uma import UMAError
from uma.message import ResourceSetResponse
from uma.message import ResourceSetDescription
from uma.message import StatusResponse

__author__ = 'roland'

logger = logging.getLogger(__name__)


class ServerError(Exception):
    pass


class OtherError(Exception):
    pass


class ServiceError(UMAError):
    pass


class ResourceSetHandler(object):
    def __init__(self, dataset, client, resource_owner):
        self.dataset = dataset
        self.client = client
        self.rsd_map = {}
        self.rsid2lid = {}
        self.resource_owner = resource_owner
        self.token = {}
        self.op2scope = {}

    def _url(self, rsid=""):
        if rsid:
            return "{}/resource_set/{}".format(
                self.client.provider_info["resource_set_registration_endpoint"],
                rsid)
        else:
            return "{}/resource_set".format(
                self.client.provider_info["resource_set_registration_endpoint"])

    def get_authn(self):
        request_args = {"access_token": self.token["PAT"]}
        ht_args = self.client.client_authn_method[
            "bearer_header"](self).construct({}, request_args=request_args)

        return ht_args["headers"]["Authorization"]

    def first_args(self, rsid=""):
        """
        Used by read, delete and list
        """
        return {
            "url": self._url(rsid),
            "http_args": {"headers": {"Authorization": self.get_authn()}}}

    def com_args(self, request, method, request_args, extra_args=None,
                 http_args=None, rsid="", **kwargs):

        _args = self.first_args(rsid)

        url, body, ht_args, csi = self.client.request_info(request, method,
                                                           request_args,
                                                           extra_args,
                                                           endpoint=_args['url'],
                                                           **kwargs)

        if http_args is None:
            http_args = ht_args
        else:
            http_args.update(http_args)

        try:
            http_args["headers"].update(_args["http_args"]["headers"])
        except KeyError:
            pass

        return {"url": url, "body": body, "http_args": http_args, "csi": csi}

    def read_resource_set_description(self, rsid="",
                                      response_cls=ResourceSetResponse):
        """
        Reads a resource set description from the Authorization server

        :returns: A ResourceSetDescription instance
        """
        _kwargs = self.first_args(rsid)

        return self.client.request_and_return(response_cls, method="GET",
                                              **_kwargs)

    def wrap_request(self, method, **kwargs):

        try:
            reqresp = self.client.http_request(method=method, **kwargs)
        except Exception:
            raise

        if reqresp.status_code in SUCCESSFUL:
            return reqresp.text
        # elif reqresp.status_code == 302:  # Do I handle redirect ? or
        #     pass
        elif reqresp.status_code == 500:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise ServerError("Server ERROR: Something went wrong: {}".format(
                reqresp.text))
        elif reqresp.status_code in [400, 401]:
            raise ServiceError("Service ERROR: Something went wrong: {}".format(
                reqresp.text))
        else:
            logger.error("(%d) %s" % (reqresp.status_code, reqresp.text))
            raise OtherError("HTTP ERROR: %s [%s] on %s" % (
                reqresp.text, reqresp.status_code, reqresp.url))

    def delete_resource_set_description(self, rsid):
        """
        Removes a resource set description from the Authorization server

        :param rsid:
        :returns: True if successful
        """
        _kwargs = self.first_args(rsid)

        try:
            resp = self.client.http_request(method="DELETE", **_kwargs)
        except Exception:
            raise

        if resp.status == "200":
            return True
        else:
            return False

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

        _kwargs = self.first_args()

        return self.client.http_request(method="GET", **_kwargs)

    def is_resource_set_changed(self, rsid, val):
        pass

    def create_resource_set_description(self, request=ResourceSetDescription,
                                        body_type="json", method="POST",
                                        request_args=None,
                                        extra_args=None, http_args=None,
                                        response_cls=ResourceSetResponse,
                                        **kwargs):

        _kwargs = self.com_args(request, method, request_args,
                                extra_args, http_args,
                                content_type='json', **kwargs)

        return self.client.request_and_return(response_cls, method, body_type,
                                              **_kwargs)

    def register_init(self, info_filter=None, scopes=None):
        """

        """
        if info_filter is None:
            info_filter = {"prim": self.resource_owner}
        else:
            info_filter.update({"prim": self.resource_owner})

        if info_filter == {}:
            res_set_desc = {}
        else:
            if not scopes:
                scopes = list(self.dataset.scopes2op.keys())

            res_set_desc = self.dataset.build_resource_set_descriptions(
                scopes=scopes, **info_filter)

        return res_set_desc

    def register_resource_set_description(self, info_filter=None, scopes=None):
        res_set_desc = self.register_init(info_filter, scopes)
        for lid, _desc in res_set_desc.items():
            res = self.create_resource_set_description(request_args=_desc)
            sr = StatusResponse().from_json(res.message)
            assert res.status == "201 Created"

            # The resource server should keep a map between resource and AS (
            # _rev,_id)
            rsid = sr['_id']
            self.rsd_map[lid] = {'_id': rsid, 'resource_set_desc': _desc}
            self.rsid2lid[rsid] = lid

    def get_info(self, *args):
        return self.dataset.get(*args)

    def query2permission_registration_request_primer(self, operation, path,
                                                     query):
        assert path == self.resource_owner
        attr = parse_qs(query)["attr"]
        return self.dataset.query2permission_registration_request_primer(
            self.resource_owner, self.op2scope[operation], attr)
