#!/usr/bin/env python

import urllib.request, urllib.parse, urllib.error
import requests
from uma.resourcesrv import DESC_BASE

__author__ = 'roland'

# User registering the AS at the RS
s = urllib.parse.quote("http://localhost:8088/")

# response should be a 200 OK
resp1 = requests.request("GET", "http://localhost:8089/rp?url=%s&acr=linda" % s)
#resp1 = requests.request("GET", "http://localhost:8089/rp?url=%s&acr=hans" % s)

# The user registers allowed access
if resp1.status_code == 200:
    # Assign some permissions
    AS = "http://localhost:8088/permreg"
    url = "%s?%s" % (AS, urllib.parse.urlencode({
        "sp_entity_id": "https://localhost:8092/sp.xml", "perm": DESC_BASE,
        "rsname": "linda.lindgren@example.com"}))
    http_args = {"auth": ("linda.lindgren@example.com", "krall")}
    resp2 = requests.request("GET", url, **http_args)
    if resp2.status_code >= 300:
        print(resp2.status_code, resp2.text)
else:
    print(resp1.status_code, resp1.text)