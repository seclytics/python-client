from .ioc import Ioc


class Asn(Ioc):
    @property
    def asn_descrpition(self):
        if 'asn' not in self.intel:
            return None
        return self.intel['asn']['description']

    @property
    def asn_number(self):
        if 'asn' not in self.intel:
            return None
        return self.intel['asn']['number']

    @property
    def country_name(self):
        if 'country' not in self.intel:
            return None
        return self.intel['country']['name']

    @property
    def country_code(self):
        if 'country' not in self.intel:
            return None
        return self.intel['country']['code']

    @property
    def registry_code(self):
        if 'rir' not in self.intel:
            return None
        return self.intel['rir']['code']

    @property
    def registry_name(self):
        if 'rir' not in self.intel:
            return None
        return self.intel['rir']['name']

    @property
    def cidrs(self):
        if 'context' not in self.intel:
            return None
        return self.intel['context']['cidrs']
