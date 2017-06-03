from .ioc import Ioc


class FileHash(Ioc):
    @property
    def hash(self):
        return self['hash']

    @property
    def names(self):
        return self._namespaced_values(u'names')

    @property
    def file_types(self):
        return self._namespaced_values(u'file_types')

    @property
    def hostnames(self):
        return self._namespaced_values(u'hostnames')

    @property
    def ips(self):
        return self._namespaced_values(u'ips')
