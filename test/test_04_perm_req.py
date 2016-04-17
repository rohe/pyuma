import pytest

from uma.message import PermissionRegistrationRequest
from uma.permission_request import PermissionRequests

__author__ = 'roland'

READ = 'http://example.org/uma/read'
WRITE = 'http://example.org/uma/write'

class TestPermReq(object):
    @pytest.fixture(autouse=True)
    def create_db(self):
        self.pr = PermissionRequests()

    def test_simple(self):
        prreq = PermissionRegistrationRequest(resource_set_id='1',
                                              scopes=[READ])
        self.pr['ticket']= [prreq]

        _prreq = self.pr['ticket']

        assert [prreq] == _prreq
        assert list(self.pr.keys()) == ['ticket']
        assert self.pr.ticket2rsid('ticket') == ['1']

        req = self.pr.rsid2requests('1')
        assert list(req.keys()) == ['ticket']
        assert req['ticket'] == [prreq]

        del self.pr['ticket']

        try:
            self.pr['ticket']
        except KeyError:
            pass
        else:
            assert False

        assert self.pr.len() == 0
        assert list(self.pr.keys()) == []

    def test_requestor(self):
        prreq = PermissionRegistrationRequest(resource_set_id='1',
                                              scopes=[READ])
        self.pr['ticket1']= [prreq]
        prreq = PermissionRegistrationRequest(resource_set_id='2',
                                              scopes=[READ, WRITE])
        self.pr['ticket2']= [prreq]

        assert self.pr.len() == 2
        assert set(self.pr.keys()) == {'ticket1', 'ticket2'}

        self.pr.bind_requestor_to_ticket('requestor', 'ticket1')

        assert self.pr.requestor2tickets('requestor') == ['ticket1']

        assert self.pr.rsid2requestor('1') == ['requestor']

        self.pr.bind_requestor_to_ticket('requestor', 'ticket2')

        assert self.pr.requestor2tickets('requestor') == ['ticket1',
                                                          'ticket2']

        assert self.pr.rsid2requestor('2') == ['requestor']

        del self.pr['ticket1']

        assert self.pr.requestor2tickets('requestor') == ['ticket2']
