import pytest
from uma.resourceset import ResourceSetHandler

__author__ = 'roland'


class TestResourceSetHandler(object):
    @pytest.fixture(autouse=True)
    def create_client(self):
        dataset =
        rsh = ResourceSetHandler(dataset, client, resource_owner)