import json
from uma.authzsrv import UmaAS, RSR_PATH
from uma.message import ResourceSetDescription, StatusResponse, PermissionRegistrationRequest

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

    data = ResourceSetDescription(name="stuff", scopes=ALL).to_json()

    resp = uas.resource_set_registration_endpoint_("alice", RSR_PATH, method="POST",
                                                   body=data, client_id="12345678",
                                                   if_match="xyzzy")

    rsid = json.loads(resp.message)["_id"]

    read_write = [SCOPES["read"], SCOPES["write"]]
    uas.permission_registration_endpoint_("alice", request=PermissionRegistrationRequest(resource_set_id=rsid, scopes=read_write).to_json())

    uas.store_permission("alice", "roger", {rsid: read_write})

    scopes, ts = uas.read_permission("alice", "roger", rsid)

    assert _eq(scopes, read_write)


def test_delete_resource_set():
    uas = UmaAS()

    data = ResourceSetDescription(name="stuff", scopes=ALL).to_json()

    resp = uas.resource_set_registration_endpoint_(RSR_PATH, "PUT",
                                                   body=data, owner="alice",
                                                   client_id="12345678")

    _stat = StatusResponse().from_json(resp.message)

    read_write = [SCOPES["read"], SCOPES["write"]]
    uas.store_permission("alice", "roger", "stuff", read_write)

    dresp = uas.resource_set_registration_endpoint_(RSR_PATH+_stat["_id"],
                                                    "DELETE", owner="alice",
                                                    client_id="12345678")

    scopes = uas.read_permission("alice", "roger", "stuff")


if __name__ == "__main__":
    test_inital_add()
