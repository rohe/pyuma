import os

import pytest
from oic.utils.http_util import NoContent, Created
from oic.utils.http_util import NotFound
from oic.utils.keyio import build_keyjar

from uma.authz_srv import RSR_PATH
from uma.authz_srv import UmaAS
from uma.message import PermissionRegistrationRequest
from uma.message import ResourceSetDescription
from uma.message import StatusResponse

__author__ = 'roland'

SCOPE_BASE = "http://example.com/uma"

SCOPES = {
    "read": SCOPE_BASE + "/read",
    "write": SCOPE_BASE + "/write",
    "modify": SCOPE_BASE + "/modify",
    "delete": SCOPE_BASE + "/delete"
}

ALL = [v for v in list(SCOPES.values())]


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_inital_add():
    uas = UmaAS()
    keys = [
        {"type": "RSA", "use": ["enc", "sig"]},
    ]
    #jwks, keyjar, kidd = build_keyjar(keys)
    uas.keyjar = build_keyjar(keys)[1]

    data = ResourceSetDescription(name="stuff", scopes=ALL).to_json()

    resp = uas.resource_set_registration_endpoint_(
        "alice", RSR_PATH, method="POST", body=data, client_id="12345678",
        if_match="xyzzy")
    _stat = StatusResponse().from_json(resp.message)
    rsid = _stat["_id"]

    headers = dict(resp.headers)
    assert headers["Location"] == "/{}/{}".format(RSR_PATH, rsid)

    read_write = [SCOPES["read"], SCOPES["write"]]
    resp = uas.permission_registration_endpoint_(
        owner="alice", request=PermissionRegistrationRequest(
            resource_set_id=rsid, scopes=read_write).to_json(),
        client_id="12345678")

    assert isinstance(resp, Created)

    resp = uas.store_permission(owner="alice", user="roger",
                                permissions={rsid: read_write},
                                client_id="12345678")

    scopes, ts = uas.read_permission("alice", "roger", rsid,
                                     client_id="12345678")

    assert _eq(scopes, read_write)


def test_delete_resource_set():
    uas = UmaAS()

    data = ResourceSetDescription(name="stuff", scopes=ALL).to_json()

    resp = uas.resource_set_registration_endpoint_(
        owner="alice", path=RSR_PATH, method="POST", body=data,
        client_id="12345678")

    _stat = StatusResponse().from_json(resp.message)
    rsid = _stat["_id"]

    read_write = [SCOPES["read"], SCOPES["write"]]
    uas.store_permission("alice", "roger", {rsid: read_write}, "12345678")

    resp = uas.resource_set_registration_endpoint_("alice", RSR_PATH + rsid,
                                            method="DELETE", owner="alice",
                                            client_id="12345678")
    assert isinstance(resp, NoContent)

    resp = uas.resource_set_registration_endpoint_("alice", RSR_PATH + "/" + rsid,
                                                   method="GET", owner="alice",
                                                   client_id="12345678")
    assert isinstance(resp, NotFound)

    with pytest.raises(KeyError):
        # make sure permission is removed when rs is deleted
        uas.read_permission("alice", "roger", rsid, "12345678")


if __name__ == "__main__":
    test_inital_add()
