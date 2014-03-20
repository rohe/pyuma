from uma.authzsrv import UmaAS, RSR_PATH
from uma.message import ResourceSetDescription, StatusResponse

__author__ = 'roland'

SCOPE_BASE = "http://example.com/uma"

SCOPES = {
    "read": SCOPE_BASE + "/read",
    "write": SCOPE_BASE + "/write",
    "modify": SCOPE_BASE + "/modify",
    "delete": SCOPE_BASE + "/delete"
}

ALL = [v for v in SCOPES.values()]


def _eq(l1, l2):
    return set(l1) == set(l2)


def test_inital_add():
    uas = UmaAS()

    data = ResourceSetDescription(name="stuff", scopes=ALL).to_json()

    uas.resource_set_registration_endpoint_(RSR_PATH, "PUT",
                                            body=data,
                                            owner="alice",
                                            client_id="12345678")

    read_write = [SCOPES["read"], SCOPES["write"]]
    uas.store_permission("alice", "roger", "stuff", read_write)

    scopes = uas.read_permission("alice", "roger", "stuff")

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
