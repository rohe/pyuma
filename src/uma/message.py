from oic.oauth2 import Message
from oic.oauth2 import PyoidcError
from oic.oauth2 import SINGLE_OPTIONAL_INT
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2 import REQUIRED_LIST_OF_STRINGS
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import SINGLE_OPTIONAL_STRING
from oic.oauth2 import dynreg
from oic.oic.message import msg_ser
from oic.oic.message import SINGLE_REQUIRED_INT
from oic.oic.message import SINGLE_OPTIONAL_BOOLEAN
from oic.oic.message import ProviderConfigurationResponse

__author__ = 'rolandh'


class ProviderConfiguration(Message):
    c_param = {
        "version": SINGLE_REQUIRED_STRING,
        "issuer": SINGLE_REQUIRED_STRING,
        "pat_profiles_supported": REQUIRED_LIST_OF_STRINGS,
        "aat_profiles_supported": REQUIRED_LIST_OF_STRINGS,
        "rpt_profiles_supported": REQUIRED_LIST_OF_STRINGS,
        "pat_grant_types_supported": REQUIRED_LIST_OF_STRINGS,
        "aat_grant_types_supported": REQUIRED_LIST_OF_STRINGS,
        "claim_profiles_supported": OPTIONAL_LIST_OF_STRINGS,
        "dynamic_client_endpoint": SINGLE_OPTIONAL_STRING,
        "token_endpoint": SINGLE_REQUIRED_STRING,
        "authorization_endpoint": SINGLE_REQUIRED_STRING,
        "requesting_party_claims_endpoint": SINGLE_OPTIONAL_STRING,
        "introspection_endpoint": SINGLE_REQUIRED_STRING,
        "resource_set_registration_endpoint": SINGLE_REQUIRED_STRING,
        "permission_registration_endpoint": SINGLE_REQUIRED_STRING,
        "rpt_endpoint": SINGLE_REQUIRED_STRING
        }


class OIDCProviderConfiguration(ProviderConfigurationResponse):
    c_param = ProviderConfigurationResponse.c_param.copy()
    c_param.update({
        "version": SINGLE_REQUIRED_STRING,
        "issuer": SINGLE_REQUIRED_STRING,
        "pat_profiles_supported": REQUIRED_LIST_OF_STRINGS,
        "aat_profiles_supported": REQUIRED_LIST_OF_STRINGS,
        "rpt_profiles_supported": REQUIRED_LIST_OF_STRINGS,
        "pat_grant_types_supported": REQUIRED_LIST_OF_STRINGS,
        "aat_grant_types_supported": REQUIRED_LIST_OF_STRINGS})


class Scope(Message):
    c_param = {
        "name": SINGLE_REQUIRED_STRING,
        "icon_uri": SINGLE_OPTIONAL_STRING,
        "subscopes": OPTIONAL_LIST_OF_STRINGS
    }


def msg_list_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, basestring):
            res = []
            if sformat == "dict":
                for _val in val:
                    res.append(Message().from_dict(_val))
            else:
                for _val in val:
                    res.append(Message().from_json(_val))
            return res
        else:
            pass
    return Message().deserialize(val, sformat)

OPTIONAL_MESSAGE = ([Message], False, msg_ser, msg_list_deser, False)


class ResourceSetDescription(Message):
    c_param = {
        "name": SINGLE_REQUIRED_STRING,
        "icon_uri": SINGLE_OPTIONAL_STRING,
        "scopes": REQUIRED_LIST_OF_STRINGS,
        "type": SINGLE_OPTIONAL_STRING,
        "_id": SINGLE_OPTIONAL_STRING,
        "_rev": SINGLE_OPTIONAL_STRING,
    }


class StatusResponse(Message):
    c_param = {
        "status": SINGLE_REQUIRED_STRING,
        "_id": SINGLE_REQUIRED_STRING,
        "_rev": SINGLE_REQUIRED_STRING,
        "policy_uri": SINGLE_OPTIONAL_STRING
    }


class AuthzDescription(Message):
    c_param = {
        "resource_set_id": SINGLE_REQUIRED_STRING,
        "entity": SINGLE_OPTIONAL_STRING,
        "scopes": REQUIRED_LIST_OF_STRINGS,
        "expires_at": SINGLE_REQUIRED_INT,
        "issued_at": SINGLE_OPTIONAL_INT,
    }


class IntrospectionRequest(Message):
    c_param = {
        "token": SINGLE_REQUIRED_STRING,
        "resource_id": SINGLE_OPTIONAL_STRING,
        "token_type_hint": SINGLE_OPTIONAL_STRING
    }


def adesc_deser(val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, basestring):
            res = []
            if sformat == "dict":
                for _val in val:
                    res.append(AuthzDescription().from_dict(_val))
            else:
                for _val in val:
                    res.append(AuthzDescription().from_json(_val))
            return res
        else:
            pass
    return Message().deserialize(val, sformat)


def adesc_ser(inst, sformat, lev=0):
    if sformat in ["urlencoded", "json"]:
        if isinstance(inst, dict) or isinstance(inst, AuthzDescription):
            res = inst.serialize(sformat, lev)
        else:
            res = inst
    elif sformat == "dict":
        if isinstance(inst, AuthzDescription):
            res = inst.serialize(sformat, lev)
        elif isinstance(inst, dict):
            res = inst
        else:
            raise ValueError("%s" % type(inst))
    else:
        raise PyoidcError("Unknown sformat")

    return res

OPTIONAL_PERM_LIST = ([AuthzDescription], False, adesc_ser, adesc_deser, False)


class IntrospectionResponse(Message):
    c_param = {
        "valid": SINGLE_OPTIONAL_BOOLEAN,
        "expires_at": SINGLE_OPTIONAL_INT,
        "issued_at": SINGLE_OPTIONAL_INT,
        "permissions": OPTIONAL_PERM_LIST,
    }


class PermissionRegistrationRequest(Message):
    c_param = {
        "resource_set_id": SINGLE_REQUIRED_STRING,
        "scopes": REQUIRED_LIST_OF_STRINGS
    }


class PermissionRegistrationResponse(Message):
    c_param = {"ticket": SINGLE_REQUIRED_STRING}


class RPTRequest(Message):
    c_param = {}


class RPTResponse(Message):
    c_param = {"rpt": SINGLE_REQUIRED_STRING}


class AuthorizationDataRequest(Message):
    c_param = {"rpt": SINGLE_REQUIRED_STRING,
               "ticket": SINGLE_REQUIRED_STRING}


class AuthorizationDataResponse(Message):
    c_param = {"rpt": SINGLE_OPTIONAL_STRING}


class ErrorResponse(Message):
    c_param = {
        "status": SINGLE_REQUIRED_STRING,
        "error": SINGLE_REQUIRED_STRING,
        "error_description": SINGLE_OPTIONAL_STRING,
        "error_uri": SINGLE_OPTIONAL_STRING
    }


class RequestingPartyClaimsRequest(Message):
    c_param = {
    }


class RequestingPartyClaimsResponse(Message):
    c_param = {
    }

MSG = {
    "ProviderConfiguration": ProviderConfiguration,
    "Scope": Scope,
    "ResourceSetDescription": ResourceSetDescription,
    "StatusResponse": StatusResponse,
    "IntrospectionRequest": IntrospectionRequest,
    "IntrospectionResponse": IntrospectionResponse,
    "PermissionRegistrationRequest": PermissionRegistrationRequest,
    "PermissionRegistrationResponse": PermissionRegistrationResponse,
    "RPTResponse": RPTResponse,
    "RPTRequest": RPTRequest,
    "AuthorizationDataRequest": AuthorizationDataRequest,
    "AuthorizationDataResponse": AuthorizationDataResponse,
    "RequestingPartyClaimsRequest": RequestingPartyClaimsRequest,
    "RequestingPartyClaimsResponse": RequestingPartyClaimsResponse
}


def factory(msgtype):
    try:
        return MSG[msgtype]
    except KeyError:
        return dynreg.factory(msgtype)
