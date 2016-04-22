from oic import rndstr
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import KeyJar
from uma.adb import ADB
from uma.authz_db import PermissionDescription
from uma.message import PermissionRegistrationRequest, ResourceSetDescription

__author__ = 'roland'

JWKS = {"keys": [
    {
        "d": "vT9bnSZ63uIdaVsmZjrbmcvrDZG-_qzVQ1KmrSSC398sLJiyaQKRPkmBRvV"
             "-MGxW1MVPeCkhnSULCRgtqHq"
             "-zQxMeCviSScHTKOuDYJfwMB5qdOE3FkuqPMsEVf6EXYaSd90"
             "-O6GOA88LBCPNR4iKxsrQ6LNkawwiJoPw7muK3TbQk9HzuznF8WDkt72CQFxd4eT"
             "6wJ97xpaIgxZce0oRmFcLYkQ4A0pgVhF42zxJjJDIBj_ZrSl5_qZIgiE76PV4hjH"
             "t9Nv4ZveabObnNbyz9YOiWHiOLdYZGmixHuauM98NK8udMxI6IuOkRypFhJzaQZF"
             "wMroa7ZNZF-mm78VYQ",
        "dp":
            "wLqivLfMc0FBhGFFRTb6WWzDpVZukcgOEQGb8wW3knmNEpgch699WQ4ZY_ws1xSbv"
            "QZtbx7MaIBXpn3qT1LYZosoP5oHVTAvdg6G8I7zgWyqj-nG4evciuoeAa1Ff52h4-"
            "J1moZ6FF2GelLdjXHoCbjIBjz_VljelSqOk5Sh5HU",
        "dq": "KXIUYNfDxwxv3A_w1t9Ohm92gOs-UJdI3_IVpe4FauCDrJ4mqgsnTisA15KY"
              "-9fCEvKfqG571WK6EKpBcxaRrqSU0ekpBvgJx8o3MGlqXWj-Lw0co8N9_"
              "-fo1rYx_8g-wCRrm5zeA5pYJdwdhOBnmKOqw_GsXJEcYeUod1xkcfU",
        "e": "AQAB",
        "ext": "true",
        "key_ops": "sign",
        "kty": "RSA",
        "n":
            "wl0DPln-EFLqr_Ftn6A87wEQAUVbpZsUTN2OCEsJV0nhlvmX3GUzyZx5UXdlM3Dz68PfUWCgfx67Il6sURqWVCnjnU-_gr3GeDyzedj-lZejnBx-lEy_3j6B98SbcDfkJF6saXnPd7_kgilJT1_g-EVI9ifFB1cxZXHCd2WBeRABSCprAlCglF-YmnUeeDs5K32z2ckVjadF9BG27CO5UfNq0K8jI9Yj_coOhM9dRNrQ9UVZNdQVG-bAIDhB2y2o3ASGwqchHouIxv5YZNGS0SMJL5t0edh483q1tSWPqBw-ZeryLztOedBBzSuJk7QDmL1B6B7KKUIrlUYJmVsYzw",
        "p":
            "6MEg5Di_IFiPGKvMFRjyx2t7YAOQ4KfdIkU_Khny1t1eCG5O07omPe_jLU8I5fPaD5F5HhWExLNureHD4K6LB18JPE3VE8chQROiRSNPZo1-faUvHu-Dy0pr7I-TS8pl_P3vop1KelIbGwXhzPIRKQMqCEKi3tLJt4R_MQ18Dx0",
        "q":
            "1cZVPpUbf4p5n4cMv_kERCPh3cieMs4aVojgh3feAiJiLwWWL9Pc43oJUekK44aWMnbs68Y4kqXtc52PMtBDzVp0Gjt0lCY3M7MYRVI4JhtknqvQynMKQ2nKs3VldvVfY2SxyUmnRyEolQUGRA7rRMUyPb4AXhSR7oroRrJD59s",
        "qi": "50PhyaqbLSczhipWiYy149sLsGlx9cX0tnGMswy1JLam7nBvH4"
              "-MWB2oGwD2hmG-YN66q-xXBS9CVDLZZrj1sonRTQPtWE"
              "-zuZqds6_NVlk2Ge4_IAA3TZ9tvIfM5FZVTOQsExu3_LX8FGCspWC1R"
              "-zDqT45Y9bpaCwxekluO7Q",
        'kid': 'sign1'
    }, {
        "k":
            b"YTEyZjBlMDgxMGI4YWU4Y2JjZDFiYTFlZTBjYzljNDU3YWM0ZWNiNzhmNmFlYTNkNTY0NzMzYjE",
        "kty": "oct",
        "use": "sig"
    }]}

issuer = 'https://as.example.org'

kb = KeyBundle(JWKS["keys"])
KEYJAR = KeyJar()
KEYJAR.issuer_keys[''] = [kb]

READ = 'http://example.org/uma/read'
WRITE = 'http://example.org/uma/write'

RESSRV = 'https://example.com/rs'


def test_senario_1():
    # create ADB instance
    adb = ADB(KEYJAR, 3600, issuer, RESSRV)

    # register resource set
    rsd = ResourceSetDescription(name='foo', scopes=[READ, WRITE])
    status = adb.resource_set.create(rsd.to_json(), 'alice')
    rsid = status['_id']

    # assume no authorization decisions has been made
    # accessing a resource set will eventually result in a ticket being issued
    prreq = PermissionRegistrationRequest(resource_set_id=rsid, scopes=[READ])
    ticket = rndstr(16)
    adb.permission_requests[ticket] = [prreq]

    # Still no authz dec. So this should fail
    assert adb.issue_rpt(ticket, 'roger') is None

    # Authz dec made
    permission = {'resource_set_id': rsid, 'scopes': [READ]}
    adb.store_permission(permission, 'alice', 'roger')

    # Get an RPT. This should now work
    rpt = adb.issue_rpt(ticket, 'roger')
    assert rpt

    # later use the RPT, turn into authz descriptions
    ad = adb.introspection(rpt)

    assert len(ad) == 1
    assert ad[0]['desc']['resource_set_id'] == rsid
    assert ad[0]['desc']['scopes'] == [READ]

    # Get an RPT. This should not work since the ticket is 'one time use'
    rpt = adb.issue_rpt(ticket, 'roger')
