#!/usr/bin/env python

import urllib
import requests
from uma.resourcesrv import DESC_BASE

__author__ = 'roland'

AS = "http://localhost:8088"
RS = "http://localhost:8089"

# User registering the AS at the RS
s = urllib.quote(AS)

# response should be a 200 OK
resp1 = requests.request("GET", "%s/rp?url=%s&acr=linda" % (RS, s))
#resp1 = requests.request("GET", "http://localhost:8089/rp?url=%s&acr=hans" % s)

SP = "https://localhost:8092/sp.xml"
IDP = "http://localhost:8090"
USER = "linda.lindgren@example.com"

# The user registers allowed access
if resp1.status_code == 200:
    # Assign some permissions
    url = "%s/permreg?%s" % (AS, urllib.urlencode({
        "sp_entity_id": SP, "perm": DESC_BASE,
        "rsname": USER}))
    http_args = {"auth": (USER, "krall")}
    resp2 = requests.request("GET", url, **http_args)
    if resp2.status_code == 200:
        # Asking for info from IdP UMA Client
        obj = urllib.quote("%s@%s" % (USER, SP))
        resp3 = requests.request("GET", "%s/info/%s" % (IDP, obj))

        if resp3.status_code == 200:
            print resp3.text
            # get resource sets
            resp4 = requests.request("GET", "%s/resset/%s" % (
                AS, urllib.quote(USER)))
            print resp4.text
            # get assigned permissions
            resp4 = requests.request("GET", "%s/permits/%s" % (
                AS, urllib.quote(USER)))
            print resp4.text
        else:
            print resp3.status_code, resp3.text
    else:
        print resp2.status_code, resp2.text
else:
    print resp1.status_code, resp1.text

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
