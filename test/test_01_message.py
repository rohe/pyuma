from uma.message import AuthenticationContext
from uma.message import ErrorDetails
from uma.message import IntrospectionResponse
from uma.message import RequiredClaims
from uma.message import RequestingPartyClaims
from uma.message import ResourceSetDescription
from uma.message import ScopeDescription

__author__ = 'rolandh'


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_scope():
    scope = ScopeDescription(
        name="View", icon_uri="http://www.example.com/icons/reading-glasses")

    msg = scope.to_json()

    _scope = ScopeDescription().deserialize(msg, "json")

    assert _eq(list(_scope.keys()), ["name", "icon_uri"])


def test_resource_set_description():
    msg = """{
     "name": "Photo Album",
     "icon_uri": "http://www.example.com/icons/flower.png",
     "scopes": [
       "http://photoz.example.com/dev/scopes/view",
       "http://photoz.example.com/dev/scopes/all"
     ],
     "type": "http://www.example.com/rsets/photoalbum"
    }"""

    rsc_set = ResourceSetDescription().deserialize(msg, "json")

    assert _eq(list(rsc_set.keys()), ["name", "icon_uri", "scopes", "type"])
    assert rsc_set["name"] == "Photo Album"
    assert rsc_set["icon_uri"] == "http://www.example.com/icons/flower.png"
    assert _eq(rsc_set["scopes"], ["http://photoz.example.com/dev/scopes/view",
                                   "http://photoz.example.com/dev/scopes/all"])
    assert rsc_set["type"] == "http://www.example.com/rsets/photoalbum"


def test_introspection_response():
    msg = """{
       "valid": true,
       "expires_at": 1256953732,
       "issued_at": 1256912345,
       "permissions": [
         {
           "resource_set_id": "112210f47de98100",
           "scopes": [
             "http://photoz.example.com/dev/actions/view",
             "http://photoz.example.com/dev/actions/all"
            ],
           "expires_at" : 1256923456
         }
       ]
      }"""

    ir = IntrospectionResponse().from_json(msg)
    # print(ir)
    assert ir["valid"] is True
    assert ir["expires_at"] == 1256953732

    perm = ir["permissions"]
    assert len(perm) == 1
    assert perm[0]["resource_set_id"] == "112210f47de98100"

    resp = ir.to_json()
    # print(resp)
    assert resp

    ir2 = IntrospectionResponse(**ir.to_dict())
    assert ir2["valid"] is True
    assert ir2["expires_at"] == 1256953732

    perm = ir2["permissions"]
    assert len(perm) == 1
    assert perm[0]["resource_set_id"] == "112210f47de98100"


def test_deser_error_details():
    msg = """{
   "authentication_context": {
     "required_acr": ["https://example.com/acrs/LOA3.14159"]
   },
   "requesting_party_claims": {
     "required_claims": [
       {
         "name": "email23423453ou453",
         "friendly_name": "email",
         "claim_type": "urn:oid:0.9.2342.19200300.100.1.3",
         "claim_token_format":
["http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken"],
         "issuer": ["https://example.com/idp"]
       }
     ],
     "redirect_user": true,
     "ticket": "016f84e8-f9b9-11e0-bd6f-0021cc6004de"
   }
 }"""

    ed = ErrorDetails().from_json(msg)
    assert ed
    assert _eq(list(ed.keys()), ['authentication_context',
                                 'requesting_party_claims'])
    ed['authentication_context'].to_dict() == {
        'required_acr': ['https://example.com/acrs/LOA3.14159']}

    rpc = ed['requesting_party_claims']
    assert _eq(list(rpc.keys()), ['required_claims', 'redirect_user', 'ticket'])
    assert rpc["redirect_user"] == True
    assert rpc['ticket'] == '016f84e8-f9b9-11e0-bd6f-0021cc6004de'
    assert len(rpc['required_claims']) == 1
    rc = rpc['required_claims'][0]
    assert _eq(list(rc.keys()), ['name', 'friendly_name', 'claim_type',
                                 'claim_token_format', 'issuer'])
    assert rc["name"] == 'email23423453ou453'
    assert rc['friendly_name'] == 'email'
    assert rc['claim_type'] == 'urn:oid:0.9.2342.19200300.100.1.3'
    assert rc['claim_token_format'] == [
        "http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken"]
    assert rc['issuer'] == ["https://example.com/idp"]


def test_ser_error_details():
    rc = RequiredClaims(
        name="email23423453ou453", friendly_name="email",
        claim_type="urn:oid:0.9.2342.19200300.100.1.3",
        claim_token_format=[
            "http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken"
        ],
        issuer=["https://example.com/idp"])

    rcp = RequestingPartyClaims(
        required_claims=[rc], redirect_user=True,
        ticket='016f84e8-f9b9-11e0-bd6f-0021cc6004de')
    ed = ErrorDetails(requesting_party_claims=rcp,
                      authentication_context=AuthenticationContext(
                          required_acr=["https://example.com/acrs/LOA3.14159"]))

    msg = ed.to_json()

    _ed = ErrorDetails().from_json(msg)
    assert _eq(list(_ed.keys()), ['authentication_context',
                                  'requesting_party_claims'])
    _ed['authentication_context'].to_dict() == {
        'required_acr': ['https://example.com/acrs/LOA3.14159']}

    rpc = _ed['requesting_party_claims']
    assert _eq(list(rpc.keys()), ['required_claims', 'redirect_user', 'ticket'])
    assert rpc["redirect_user"] == True
    assert rpc['ticket'] == '016f84e8-f9b9-11e0-bd6f-0021cc6004de'
    assert len(rpc['required_claims']) == 1
    rc = rpc['required_claims'][0]
    assert _eq(list(rc.keys()), ['name', 'friendly_name', 'claim_type',
                                 'claim_token_format', 'issuer'])
    assert rc["name"] == 'email23423453ou453'
    assert rc['friendly_name'] == 'email'
    assert rc['claim_type'] == 'urn:oid:0.9.2342.19200300.100.1.3'
    assert rc['claim_token_format'] == [
        "http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken"]
    assert rc['issuer'] == ["https://example.com/idp"]
