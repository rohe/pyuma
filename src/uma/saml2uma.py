from oic.oauth2 import Message
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import SINGLE_OPTIONAL_STRING

__author__ = 'rolandh'


class ResourceRequest(Message):
    c_param = {
        "rpt": SINGLE_OPTIONAL_STRING,
        "resource": SINGLE_REQUIRED_STRING,
    }


class ResourceResponse(Message):
    c_param = {
        "resource": SINGLE_REQUIRED_STRING
    }


class ErrorResponse(Message):
    c_param = {
        "as_uri": SINGLE_OPTIONAL_STRING,
        "host_id": SINGLE_REQUIRED_STRING,
        "error": SINGLE_REQUIRED_STRING,
        "ticket": SINGLE_OPTIONAL_STRING
    }


