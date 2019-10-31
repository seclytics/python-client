from .host import Host


class Domain(Host):

    @property
    def suffix(self):
        return self.intel['suffix']

    @property
    def tld(self):
        return self.intel['tld']

    @property
    def ips(self):
        if 'context' not in self.intel:
            return None
        return self.intel['context']['ips']
