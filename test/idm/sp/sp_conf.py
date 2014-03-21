from saml2 import BINDING_HTTP_REDIRECT
from saml2 import BINDING_HTTP_POST
from saml2.extension.idpdisc import BINDING_DISCO
from saml2.saml import NAME_FORMAT_URI

BASE= "https://localhost:8092"
#BASE = "https://lingon.ladok.umu.se:8087"

CONFIG = {
    "entityid": "%s/sp.xml" % BASE,
    "description": "My SP",
    "service": {
        "sp": {
            "name": "Rolands SP",
            "endpoints": {
                "assertion_consumer_service": [
                    ("%s/acs/redirect" % BASE, BINDING_HTTP_REDIRECT),
                    ("%s/acs/post" % BASE, BINDING_HTTP_POST)
                ],
                "single_logout_service": [(BASE + "/slo",
                                           BINDING_HTTP_REDIRECT)],
                "discovery_response": [
                    ("%s/disco" % BASE, BINDING_DISCO)
                ]
            },
            "required_attributes": ["surname", "givenname",
                                    "edupersonaffiliation"],
            "optional_attributes": ["title"],
        }
    },
    "debug": 1,
    "key_file": "pki/mykey.pem",
    "cert_file": "pki/mycert.pem",
    "metadata": {"local": ["../idp/idp.xml"]},
    # -- below used by make_metadata --
    "organization": {
        "name": "Exempel AB",
        "display_name": [("Exempel AB", "se"), ("Example Co.", "en")],
        "url": "http://www.example.com/roland",
    },
    "contact_person": [
        {
            "given_name": "John",
            "sur_name": "Smith",
            "email_address": ["john.smith@example.com"],
            "contact_type": "technical",
        },
    ],
    "xmlsec_binary": "/opt/local/bin/xmlsec1",
    "name_form": NAME_FORMAT_URI,
    "logger": {
        "rotating": {
            "filename": "sp.log",
            "maxBytes": 1000000,
            "backupCount": 5,
        },
        "loglevel": "debug",
    }
}
