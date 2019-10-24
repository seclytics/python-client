from .host import Host


class Url(Host):

    @property
    def ips(self):
        if 'context' not in self.intel:
            return None
        return self.intel['context']['ips']
