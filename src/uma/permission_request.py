__author__ = 'roland'


class PermissionRequests(object):
    """
    Stores all pending Permission requests
    """

    def __init__(self):
        self._db = {}
        self.requestor_tickets = {}
        self.ticket2requestor = {}

    def __setitem__(self, ticket, pr_req):
        """
        :param pr_req: A list of Permission Registration Request instances
        """
        self._db[ticket] = pr_req

    def __getitem__(self, ticket):
        """
        :param ticket: The ticket returned when the Permission Registration
            Request was made
        :return: One or more uma.message.PermissionRegistrationRequest instances
        """
        return self._db[ticket]

    def rsid2requests(self, rsid):
        """
        :param rsid: Resource set identifier
        :return: A dictionary with tickets as keys and
            PermissionRegistrationRequest instances as values
        """
        res = {}
        for _tick, req_list in self._db.items():
            for req in req_list:
                if rsid == req['resource_set_id']:
                    try:
                        res[_tick].append(req)
                    except KeyError:
                        res[_tick] = [req]

        return res

    def ticket2rsid(self, ticket):
        try:
            return [rsd['resource_set_id'] for rsd in self._db[ticket]]
        except KeyError:
            return []

    def bind_requestor_to_ticket(self, requestor, ticket):
        try:
            self.requestor_tickets[requestor].append(ticket)
        except KeyError:
            self.requestor_tickets[requestor] = [ticket]

        self.ticket2requestor[ticket] = requestor

    def requestor2tickets(self, requestor):
        return [t for t in self.requestor_tickets[requestor]]

    def __delitem__(self, ticket):
        try:
            req = self.ticket2requestor[ticket]
        except KeyError:
            pass
        else:
            self.requestor_tickets[req].remove(ticket)
            del self.ticket2requestor[ticket]

        try:
            del self._db[ticket]
        except KeyError:
            pass

    def len(self):
        return len(self._db)

    def keys(self):
        return self._db.keys()

    def rsid2requestor(self, rsid):
        res = []
        for t in self.rsid2requests(rsid).keys():
            try:
                user = self.ticket2requestor[t]
            except KeyError:
                pass
            else:
                if user not in res:
                    res.append(user)
        return res
