from .cidr import Cidr


class Ip(Cidr):
    @property
    def score(self):
        if 'score' not in self.intel:
            return None
        return self.intel['score']['value']
