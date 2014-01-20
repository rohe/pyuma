from uma.authzsrv import OAuth2UmaAS
from uma.client import Client
from uma.resourcesrv import ResourceServer1C

__author__ = 'roland'


class UmaCAS(object):
    def __init__(self, name, sdb, cdb, authn_broker, authz,
                 client_authn, symkey, urlmap=None, as_keyjar=None,
                 as_configuration=None, base_url="",
                 client_authn_methods=None, authn_at_registration="",
                 client_info_url="", secret_lifetime=86400,
                 # client conf below
                 client_id=None, ca_certs=None,
                 client_authn_method=None, c_keyjar=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope=""):

        self.authzsrv = OAuth2UmaAS(name, sdb, cdb, authn_broker, authz,
                                    client_authn, symkey, urlmap,
                                    as_keyjar, as_configuration, base_url,
                                    client_authn_methods, authn_at_registration,
                                    client_info_url, secret_lifetime)
        self.client = Client(client_id, ca_certs, client_authn_method,
                             c_keyjar, server_info, authz_page, flow_type,
                             password, registration_info, response_type,
                             scope)

    # C <-> AS internal communication
    def rpt_endpoint(self, authn, **kwargs):
        pass

    def authorization_request_endpoint(self, request="", authn="", **kwargs):
        pass


class UmaCRS(object):
    def __init__(self, dataset, symkey="", rs_keyjar=None, baseurl="",
                 # client conf below
                 client_id=None, ca_certs=None,
                 client_authn_method=None, c_keyjar=None,
                 server_info=None, authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope=""):

        self.ressrv = ResourceServer1C.__init__(
            dataset, symkey, client_id, ca_certs, client_authn_method,
            rs_keyjar, server_info, authz_page, flow_type, password,
            registration_info, response_type, scope, baseurl)

        self.client = Client(client_id, ca_certs, client_authn_method,
                             c_keyjar, server_info, authz_page, flow_type,
                             password, registration_info, response_type,
                             scope)

    def dataset_access(self, owner, environ, resource):
        pass
