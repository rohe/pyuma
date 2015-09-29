__author__ = 'rolandh'

AAT = "uma_authorization"
PAT = "uma_protection"


class UMAError(Exception):
    pass


class Expired(UMAError):
    pass