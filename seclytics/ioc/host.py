from .ioc import Ioc


class Host(Ioc):
    @property
    def domain(self):
        return self['domain']

    @property
    def hostname(self):
        return self['hostname']
