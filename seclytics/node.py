"""Wraps any IOC"""
from .ioc import Ip, Cidr, Asn, Host, FileHash, Domain, Url
from . import __version__

class Node(object):
    """Node wraps each IOC

    Allows us to call connections without creating circular dependencies.

    Attributes:
        api_client: the seclytics api client
        _wrapped_obj: the ioc_object
    """
    def __init__(self, api_client, obj):
        '''
        Wrapper constructor.
        @param obj: object to wrap
        '''
        # wrap the object
        self.api_client = api_client
        self._wrapped_obj = obj

    def __getattr__(self, attr):
        # NOTE do not use hasattr, it goes into infinite recurrsion
        if attr in self.__dict__:
            return getattr(self, attr)
        # proxy to the wrapped object
        return getattr(self._wrapped_obj, attr)

    @property
    def connections(self):
        """Iterates over the connections loading nodes"""
        if 'connections' not in self.intel:
            return
        for edge in self.intel['connections']:
            yield self.build_for_row(self.api_client, edge)

    @staticmethod
    def build_for_row(api_client, row):
        """Use the type attribute to build a Node

        returns:
            Node object of IOC
        """
        type_to_module = {
            'asn': Asn,
            'cidr': Cidr,
            'domain': Domain,
            'file': FileHash,
            'host': Host,
            'ip': Ip,
            'url': Url
        }
        row_module = type_to_module.get(row['type'])
        if row_module:
            return Node(api_client, row_module(api_client, row))
