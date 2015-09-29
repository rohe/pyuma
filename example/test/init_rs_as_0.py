#!/usr/bin/env python

import urllib.request, urllib.parse, urllib.error
import requests

__author__ = 'roland'

# User registering the AS at the RS
s = urllib.parse.quote("http://localhost:8088/")

# response should be a 200 OK
resp1 = requests.request("GET", "http://localhost:8089/rp?url=%s&acr=linda" % s)
#resp1 = requests.request("GET", "http://localhost:8089/rp?url=%s&acr=hans" % s)

if resp1.status_code != 200:
    print(resp1.text)