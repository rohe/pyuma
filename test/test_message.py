from uma.message import Scope, IntrospectionResponse
from uma.message import ResourceSetDescription

__author__ = 'rolandh'


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_scope():
    scope = Scope(name="View",
                  icon_uri="http://www.example.com/icons/reading-glasses")

    msg = scope.to_json()

    _scope = Scope().deserialize(msg, "json")

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
    print(ir)
    assert ir["valid"] is True
    assert ir["expires_at"] == 1256953732

    perm = ir["permissions"]
    assert len(perm) == 1
    assert perm[0]["resource_set_id"] == "112210f47de98100"

    resp = ir.to_json()
    print(resp)
    assert resp

    ir2 = IntrospectionResponse(**ir.to_dict())
    assert ir2["valid"] is True
    assert ir2["expires_at"] == 1256953732

    perm = ir2["permissions"]
    assert len(perm) == 1
    assert perm[0]["resource_set_id"] == "112210f47de98100"

if __name__ == "__main__":
    test_introspection_response()