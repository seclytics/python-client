from .asn import Asn


class Cidr(Asn):
    @property
    def cidr_block(self):
        if 'cidr' not in self.intel:
            return None
        return self.intel['cidr']['block']

    @property
    def cidr_status(self):
        if 'cidr' not in self.intel:
            return None
        return self.intel['cidr']['status']

    @property
    def cidr_size(self):
        if 'cidr' not in self.intel:
            return None
        return self.intel['cidr']['size']

    @property
    def ips(self):
        if 'context' not in self.intel:
            return None
        return self.intel['context']['ips']
