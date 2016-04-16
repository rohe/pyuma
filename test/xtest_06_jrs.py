import json
import os
from io import StringIO

from oic.oauth2.message import ErrorResponse
from oic.utils.http_util import Response
from oic.utils.time_util import epoch_in_a_while
from oic.utils.time_util import utc_time_sans_frac

from uma.message import IntrospectionResponse
from uma.message import AuthzDescription
from uma.json_resource_server import JsonResourceServer
from uma.json_resource_server import DEF_SCOPES

__author__ = 'roland'

def create_alice_resource(jrs):
    body = json.dumps({"foo": "bar"})

    environ = {"REQUEST_METHOD": "POST", "REMOTE_USER": "ALICE",
               'wsgi.input': StringIO(body),
               "CONTENT_LENGTH": len(body)}

    user = "alice"
    resp = jrs.do("info/alice", environ, user=user)

    return resp

def test_init():
    jrs = JsonResourceServer("resource/", "info/", "https://example.com")
    assert jrs


def test_alice_add(tmpdir):
    root_dir = os.path.join(tmpdir.strpath, "resource")
    jrs = JsonResourceServer(root_dir, "info/", "https://example.com")

    resp = create_alice_resource(jrs)
    assert not isinstance(resp, ErrorResponse)


def test_roger_read(tmpdir):
    root_dir = os.path.join(tmpdir.strpath, "resource/")
    jrs = JsonResourceServer(root_dir, "info/", "https://example.com")

    create_alice_resource(jrs)

    environ = {"REQUEST_METHOD": "GET", "REMOTE_USER": "ROGER"}
    ad = AuthzDescription(resource_set_id=0,
                          scopes=["http://dirg.org.umu.se/uma/scopes/read"],
                          expires_at=epoch_in_a_while(minutes=45))

    ir = IntrospectionResponse(
        valid=True,
        expires_at=epoch_in_a_while(minutes=45),
        issued_at=utc_time_sans_frac,
        permissions=[ad]
    )

    resp = jrs.do("info/alice/1", environ, permission=ir)

    assert not isinstance(resp, ErrorResponse)
    assert resp.message in ['{"foo": "bar", "_id": 1}',
                            '{"_id": 1, "foo": "bar"}']


def test_roger_create():
    jrs = JsonResourceServer("resource/", "info/", "https://example.com")

    body = json.dumps({"bar": "soap"})

    environ = {
        "REQUEST_METHOD": "POST",
        "REMOTE_USER": "ROGER",
        'wsgi.input': StringIO(body),
        "CONTENT_LENGTH": len(body)
    }
    ad = AuthzDescription(resource_set_id=0,
                          scopes=["http://dirg.org.umu.se/uma/scopes/read"],
                          expires_at=epoch_in_a_while(minutes=45))

    ir = IntrospectionResponse(
        valid=True,
        expires_at=epoch_in_a_while(minutes=45),
        issued_at=utc_time_sans_frac,
        permissions=[ad]
    )

    resp = jrs.do("info/alice/1", environ, permission=ir)

    assert isinstance(resp, ErrorResponse)


def test_alice_client_read(tmpdir):
    root_dir = os.path.join(tmpdir.strpath, "resource/")
    jrs = JsonResourceServer(root_dir, "info/", "https://example.com")
    create_alice_resource(jrs)

    body = json.dumps({"bar": "soap"})

    environ = {
        "REQUEST_METHOD": "GET",
        "REMOTE_USER": "ALICE",
        'wsgi.input': StringIO(body),
        "CONTENT_LENGTH": len(body)
    }
    ad = AuthzDescription(resource_set_id=0,
                          scopes=DEF_SCOPES,
                          expires_at=epoch_in_a_while(minutes=45))

    ir = IntrospectionResponse(
        valid=True,
        expires_at=epoch_in_a_while(minutes=45),
        issued_at=utc_time_sans_frac,
        permissions=[ad]
    )

    resp = jrs.do("info/alice/1", environ, permission=ir)

    assert not isinstance(resp, ErrorResponse)
    assert isinstance(resp, Response)


def test_roger_patch(tmpdir):
    root_dir = os.path.join(tmpdir.strpath, "resource/")
    jrs = JsonResourceServer(root_dir, "info/", "https://example.com")
    create_alice_resource(jrs)

    body = json.dumps({"bar": "soap"})

    environ = {
        "REQUEST_METHOD": "PATCH",
        "REMOTE_USER": "ROGER",
        'wsgi.input': StringIO(body),
        "CONTENT_LENGTH": len(body)
    }
    ad = AuthzDescription(resource_set_id=0,
                          scopes=[
                              "http://dirg.org.umu.se/uma/scopes/read",
                              "http://dirg.org.umu.se/uma/scopes/patch"
                          ],
                          expires_at=epoch_in_a_while(minutes=45))

    ir = IntrospectionResponse(
        valid=True,
        expires_at=epoch_in_a_while(minutes=45),
        issued_at=utc_time_sans_frac,
        permissions=[ad]
    )

    resp = jrs.do("info/alice/1", environ, permission=ir)

    assert not isinstance(resp, ErrorResponse)
    assert resp.message == '{"_id": "1"}'


def test_get_owner(tmpdir):
    root_dir = os.path.join(tmpdir.strpath, "resource/")
    jrs = JsonResourceServer(root_dir, "info/", "https://example.com",
                             ["alice"])
    jrs.index["alice"] = 1
    assert jrs.get_owner("info/alice/1") == "alice"
    assert jrs.get_owner("info/public/x") is None
