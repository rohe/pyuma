import urllib
import requests
#from oic.utils.authn.client import CLIENT_AUTHN_METHOD
#from uma.client import Client
from uma.resourcesrv import DESC_BASE

__author__ = 'roland'

# User registering the AS at the RS
s = urllib.quote("http://localhost:8088/")
# response should be a 200 OK
resp1 = requests.request("GET", "http://localhost:8089/rp?url=%s&acr=linda" % s)
#resp1 = requests.request("GET", "http://localhost:8089/rp?url=%s&acr=hans" % s)


if resp1.status_code == 200:
    # Assign some permissions
    AS = "http://localhost:8088/permreg"
    url = "%s?%s" % (AS, urllib.urlencode({
        "sp_entity_id": "sp.example.net", "perms": DESC_BASE,
        "name": "linda.lindgren@example.com"}))
    http_args = {"auth": ("linda.lindgren@example.com", "krall")}
    resp2 = requests.request("GET", url, **http_args)

    if resp2.status_code == 200:
        # Asking for info from IdP UMA Client
        resp3 = requests.request(
            "GET",
            "http://localhost:8090/info/linda.lindgren--example.com--sp.example"
            ".net")

        print resp3.text

    # Get provider_config
    #provider_info = idp_client.provider_config(as_uri)

    # register as client
    #reg_info = idp_client.register(provider_info["registration_endpoint"])

    #http_args = idp_client.init_authentication_method(
    #    {}, "client_secret_basic",
    #    user="linda.lindgren@example.com@sp.example.org",
    #    password="fornowany")
    #
    #request_args = {
    #    "response_type": "code",
    #    "scope": [idp_client.get_uma_scope("AAT"),
    #              idp_client.get_uma_scope("PAT")],
    #    "state": idp_client.state,
    #}
    #
    #idp_client.do_authorization_request(request_args=request_args,
    #                                    http_args=http_args)
