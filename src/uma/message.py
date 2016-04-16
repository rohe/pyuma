from oic.extension import message
from oic.oauth2 import AccessTokenRequest
from oic.oauth2 import Message
from oic.oauth2 import PyoidcError
from oic.oauth2 import SINGLE_OPTIONAL_INT
from oic.oauth2 import OPTIONAL_LIST_OF_STRINGS
from oic.oauth2 import REQUIRED_LIST_OF_STRINGS
from oic.oauth2 import SINGLE_REQUIRED_STRING
from oic.oauth2 import SINGLE_OPTIONAL_STRING
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
        if not isinstance(val, str):
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
        "uri": SINGLE_OPTIONAL_STRING
    }


class ResourceSetResponse(ResourceSetDescription):
    c_param = ResourceSetDescription.c_param.copy()
    c_param.update({"_id": SINGLE_REQUIRED_STRING})


class StatusResponse(Message):
    c_param = {
        "_id": SINGLE_REQUIRED_STRING,
        "user_access_policy_uri": SINGLE_OPTIONAL_STRING
    }


class AuthzDescription(Message):
    c_param = {
        "resource_set_id": SINGLE_REQUIRED_STRING,
        "scopes": REQUIRED_LIST_OF_STRINGS,
        "exp": SINGLE_REQUIRED_INT,
        "iat": SINGLE_OPTIONAL_INT,
        'nbf': SINGLE_OPTIONAL_INT
    }


class IntrospectionRequest(Message):
    c_param = {
        "token": SINGLE_REQUIRED_STRING,
        "resource_id": SINGLE_OPTIONAL_STRING,
        "token_type_hint": SINGLE_OPTIONAL_STRING
    }


def desc_deser(klass, val, sformat="urlencoded"):
    if sformat in ["dict", "json"]:
        if not isinstance(val, str):
            res = []
            if sformat == "dict":
                if isinstance(val, dict):
                    return klass().from_dict(val)
                elif isinstance(val, list):
                    for _val in val:
                        res.append(klass().from_dict(_val))
            else:
                for _val in val:
                    res.append(klass().from_json(_val))
            return res
        else:
            pass
    return Message().deserialize(val, sformat)


def desc_ser(klass, inst, sformat, lev=0):
    if sformat in ["urlencoded", "json"]:
        if isinstance(inst, dict) or isinstance(inst, klass):
            res = inst.serialize(sformat, lev)
        else:
            res = inst
    elif sformat == "dict":
        if isinstance(inst, klass):
            res = inst.serialize(sformat, lev)
        elif isinstance(inst, dict):
            res = inst
        elif isinstance(inst, list):
            res = []
            for item in inst:
                if isinstance(item, klass):
                    res.append(item.serialize(sformat, lev))
                elif isinstance(item, dict):
                    res.append(item)
                else:
                    raise ValueError("%s" % type(item))
        else:
            raise ValueError("%s" % type(inst))
    else:
        raise PyoidcError("Unknown sformat")

    return res


def adesc_ser(inst, sformat, lev=0):
    return desc_ser(AuthzDescription, inst, sformat, lev)


def adesc_deser(val, sformat="urlencoded"):
    return desc_deser(AuthzDescription, val, sformat)


OPTIONAL_PERM_LIST = ([AuthzDescription], False, adesc_ser, adesc_deser, False)


class IntrospectionResponse(Message):
    c_param = {
        "active": SINGLE_OPTIONAL_BOOLEAN,
        "exp": SINGLE_OPTIONAL_INT,
        "iat": SINGLE_OPTIONAL_INT,
        "permissions": OPTIONAL_PERM_LIST,
    }


class PermissionRegistrationRequest(Message):
    c_param = {
        "resource_set_id": SINGLE_REQUIRED_STRING,
        "scopes": REQUIRED_LIST_OF_STRINGS
    }


class PermissionRegistrationResponse(Message):
    c_param = {"ticket": SINGLE_REQUIRED_STRING}


# class RPTRequest(Message):
#    c_param = {}


class ClaimToken(Message):
    c_param = {
        "format": SINGLE_REQUIRED_STRING,
        "token": SINGLE_REQUIRED_STRING,
    }


OPTIONAL_CLAIM_TOKENS_LIST = ([ClaimToken], False, None, None, False)

# Extension grant for client credentials combined with claims about the
# Requesting Party
RQP_CLAIMS_GRANT_TYPE = "https://as.example.com/rqp_claims"


class RPTRequest(AccessTokenRequest):
    c_param = {"rpt": SINGLE_OPTIONAL_STRING,
               "ticket": SINGLE_REQUIRED_STRING,
               "claim_tokens": OPTIONAL_CLAIM_TOKENS_LIST
               }
    c_default = {"grant_type": RQP_CLAIMS_GRANT_TYPE}


class RPTResponse(Message):
    c_param = {"rpt": SINGLE_REQUIRED_STRING}


class AuthorizationDataRequest(Message):
    c_param = {"rpt": SINGLE_OPTIONAL_STRING,
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


class AuthenticationContext(Message):
    c_param = {"required_acr": REQUIRED_LIST_OF_STRINGS}


class RequiredClaims(Message):
    c_param = {
        "name": SINGLE_OPTIONAL_STRING,
        "friendly_name": SINGLE_OPTIONAL_STRING,
        "claim_type": SINGLE_OPTIONAL_STRING,
        'claim_token_format': OPTIONAL_LIST_OF_STRINGS,
        'issuer': OPTIONAL_LIST_OF_STRINGS
    }


def reqc_ser(inst, sformat, lev=0):
    return desc_ser(RequiredClaims, inst, sformat, lev)


def reqc_deser(val, sformat):
    return desc_deser(RequiredClaims, val, sformat)


REQUIRED_LIST_OF_REQUIREDCLAIMS = ([RequiredClaims], True, reqc_ser,
                                   reqc_deser, False)


class RequestingPartyClaims(Message):
    c_param = {
        'required_claims': REQUIRED_LIST_OF_REQUIREDCLAIMS,
        'redirect_user': SINGLE_OPTIONAL_BOOLEAN,
        'ticket': SINGLE_OPTIONAL_STRING
    }


def ac_ser(inst, sformat, lev=0):
    return desc_ser(AuthenticationContext, inst, sformat, lev)


def ac_deser(val, sformat):
    return desc_deser(AuthenticationContext, val, sformat)


REQUIRED_AUTHENTICATIONCONTEXT = (AuthenticationContext, True, ac_ser,
                                  ac_deser, False)


def rpc_ser(inst, sformat, lev=0):
    return desc_ser(RequestingPartyClaims, inst, sformat, lev)


def rpc_deser(val, sformat):
    return desc_deser(RequestingPartyClaims, val, sformat)


REQUIRED_REQUESTINGPARTYCLAIMS = (RequestingPartyClaims, True, rpc_ser,
                                  rpc_deser, False)


class ErrorDetails(Message):
    c_param = {
        'authentication_context': REQUIRED_AUTHENTICATIONCONTEXT,
        'requesting_party_claims': REQUIRED_REQUESTINGPARTYCLAIMS
    }


class RequestingPartyRedirect(Message):
    c_param = {
        'client_id': SINGLE_REQUIRED_STRING,
        'ticket': SINGLE_REQUIRED_STRING,
        'claims_redirect_uri': SINGLE_OPTIONAL_STRING,
        'state': SINGLE_OPTIONAL_STRING
    }


class RequestingPartyResponse(Message):
    c_param = {
        'authorization_state': SINGLE_REQUIRED_STRING,
        'ticket': SINGLE_OPTIONAL_STRING,
        'state': SINGLE_OPTIONAL_STRING
    }
    c_allowed_values = {
        "authorization_state": ["claims_submitted", 'not_authorized',
                                'need_info', 'request_submitted']}


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
    "AuthenticationContext": AuthenticationContext,
    "RequestingPartyClaims": RequestingPartyClaims,
    "ErrorResponse": ErrorResponse,
    "ErrorDetails": ErrorDetails,
    "ResourceSetResponse": ResourceSetResponse,
    'RequestingPartyRedirect': RequestingPartyRedirect,
    'RequestingPartyResponse': RequestingPartyResponse
}


def factory(msgtype):
    try:
        return MSG[msgtype]
    except KeyError:
        return message.factory(msgtype)
