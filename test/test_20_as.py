import json

import pytest
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Created
from oic.utils.keyio import build_keyjar

from uma.authz_srv import RSR_PATH
from uma.authz_srv import UmaAS
from uma.message import PermissionRegistrationRequest, AuthorizationDataRequest
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


KEYDEF = keys = [{"type": "RSA", "use": ["enc", "sig"]}]


class TestAS(object):
    @pytest.fixture(autouse=True)
    def create_db(self):
        self.uas = UmaAS()
        self.uas.keyjar = build_keyjar(KEYDEF)[1]

    def test_resource_set_registration_endpoint(self):
        rsd = ResourceSetDescription(name="stuff", scopes=ALL)

        # Register a resource set
        resp = self.uas.resource_set_registration_endpoint_(
            "alice", RSR_PATH, method="POST", body=rsd.to_json(),
            client_id="12345678", if_match="xyzzy")

        assert resp.status == '201 Created'

        # Verify that it went OK
        _stat = StatusResponse().from_json(resp.message)
        _stat.verify()
        rsid = _stat["_id"]

        # The header Location parameter shold contain a URL that can be used
        # to access the resource set description
        headers = dict(resp.headers)
        assert headers["Location"] == "/{}/{}".format(RSR_PATH, rsid)
        _path = headers["Location"]

        # list uploaded resource sets
        resp = self.uas.resource_set_registration_endpoint_(
            "alice", RSR_PATH, method="GET", client_id="12345678")

        assert resp.status == '200 OK'
        rsid_list = json.loads(resp.message)

        assert len(rsid_list) == 1
        assert rsid in rsid_list

        # get a specific resource set
        resp = self.uas.resource_set_registration_endpoint_(
            "alice", _path, method="GET", client_id="12345678")

        assert resp.status == '200 OK'
        rset = json.loads(resp.message)

        assert rsd['name'] == rset['name']

        # Upload a new version
        read_write = [SCOPES[s] for s in ['read', 'write']]
        rsd = ResourceSetDescription(name="stuff", scopes=read_write,
                                     type='document')

        resp = self.uas.resource_set_registration_endpoint_(
            "alice", _path, method="PUT", body=rsd.to_json(),
            client_id="12345678")

        assert resp.status == '200 OK'

        # Verify that it went OK
        _stat = StatusResponse().from_json(resp.message)
        _stat.verify()
        rsid = _stat["_id"]

        # make sure the change came through
        resp = self.uas.resource_set_registration_endpoint_(
            "alice", _path, method="GET", client_id="12345678")

        assert resp.status == '200 OK'
        rset = json.loads(resp.message)

        assert _eq(rset.keys(), ['name', 'scopes', 'type', '_id'])
        assert rset['type'] == rsd['type']

        # delete a resource set
        resp = self.uas.resource_set_registration_endpoint_(
            "alice", _path, method="DELETE", client_id="12345678")

        assert resp.status == '204 No Content'

    def test_permission_registration_endpoint(self):
        data = ResourceSetDescription(name="stuff", scopes=ALL).to_json()

        # Register a resource set
        resp = self.uas.resource_set_registration_endpoint_(
            "alice", RSR_PATH, method="POST", body=data, client_id="12345678",
            if_match="xyzzy")
        rsid = StatusResponse().from_json(resp.message)['_id']

        read_write = [SCOPES[s] for s in ['read', 'write']]
        perm_reg = PermissionRegistrationRequest(resource_set_id=rsid,
                                                 scopes=read_write)

        resp = self.uas.permission_registration_endpoint_(
            owner="alice", request=perm_reg.to_json(), client_id="12345678")

        assert isinstance(resp, Created)

        # Trying to register a request with an unknown rsid
        perm_reg = PermissionRegistrationRequest(
            resource_set_id='0987654321', scopes=read_write)
        resp = self.uas.permission_registration_endpoint_(
            owner="alice", request=perm_reg.to_json(), client_id="12345678")
        assert isinstance(resp, BadRequest)

    def test_rpt_endpoint(self):
        """
        A couple of things have to happen before any action can occur on
        the rpt endpoint.
        1. registration of Resource set
        2. Registration of a permission request
        3. Registration of an authorization
        """
        # (1) register resource set
        read_write = [SCOPES[s] for s in ['read', 'write']]
        rsd = ResourceSetDescription(name='foo', scopes=read_write)

        resp = self.uas.resource_set_registration_endpoint_(
            "alice", RSR_PATH, method="POST", body=rsd.to_json(),
            client_id="12345678")
        rsid = StatusResponse().from_json(resp.message)['_id']

        # (2) register a permission request
        read_write = [SCOPES[s] for s in ['read', 'write']]
        perm_reg = PermissionRegistrationRequest(resource_set_id=rsid,
                                                 scopes=read_write)

        resp = self.uas.permission_registration_endpoint_(
            owner="alice", request=perm_reg.to_json(), client_id="12345678")

        assert isinstance(resp, Created)
        ticket = json.loads(resp.message)['ticket']

        # (3) registration of authorization
        permission = {'resource_set_id': rsid, 'scopes': [SCOPES['read']],
                      'require': {'sub': 'roger'}}
        adb = self.uas.get_adb("12345678")
        adb.store_permission(permission, 'alice')

        # Get an RPT. This should now work
        req = AuthorizationDataRequest(ticket=ticket)
        resp = self.uas.rpt_endpoint_('roger', '87654321', request=req)
