import requests
from .exceptions import InvalidAccessToken
from .ioc import Ip, Cidr, Asn, Host, FileHash
from pprint import pprint


class Seclytics(object):
    base_url = 'https://api.seclytics.com'

    def __init__(self, access_token):
        self.access_token = access_token
        self.session = requests.Session()

    def _get_request(self, path, params):
        url = ''.join((self.base_url, path))
        data = None
        params[u'access_token'] = self.access_token
        if 'attributes' in params:
            params[u'attributes'] = ','.join(params[u'attributes'])
        response = self.session.get(url, params=params)
        if response.status_code == 401:
            raise InvalidAccessToken()
        if response.status_code != 200:
            print(response.status_code)
            # TODO raise server error
            return None
        data = response.json()
        return data

    def _ioc_show(self, ioc_path, ioc_id, attributes=[]):
        path = u'/%s/%s' % (ioc_path, ioc_id)
        params = {}
        if len(attributes) > 0:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'error' in response:
            return RuntimeError(response['error']['message'])
        return response

    def ip(self, ip, attributes=[]):
        response = self._ioc_show('ips', ip)
        return Node(Ip(response))

    def cidr(self, cidr, attributes=[]):
        response = self._ioc_show('cidrs', cidr)
        return Node(Cidr(response))

    def asn(self, asn, attributes=[]):
        response = self._ioc_show('asns', asn)
        return Node(Asn(response))

    def host(self, host, attributes=[]):
        response = self._ioc_show('hosts', host)
        return Node(Host(response))

    def file(self, file_hash, attributes=[]):
        response = self._ioc_show('files', file_hash)
        return Node(FileHash(response))

    def ips(self, ips=[], attributes=[]):
        path = u'/ips'
        params = {u'ids': ips}
        if len(attributes) > 0:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'data' in response:
            for row in response['data']:
                yield Node(Ip(row))


class Node(object):
    '''
    Node wraps each IOC so we can call connections without creating
    circular dependencies.
    '''
    def __init__(self, obj):
        '''
        Wrapper constructor.
        @param obj: object to wrap
        '''
        # wrap the object
        self._wrapped_obj = obj

    def __getattr__(self, attr):
        # see if this object has attr
        # NOTE do not use hasattr, it goes into
        # infinite recurrsion
        if attr in self.__dict__:
            # this object has it
            return getattr(self, attr)
        # proxy to the wrapped object
        return getattr(self._wrapped_obj, attr)

    @property
    def connections(self):
        if 'connections' not in self.intel:
            return
        for edge in self.intel['connections']:
            if edge['type'] == 'ip':
                yield Node(Ip(edge))
            elif edge['type'] == 'host':
                yield Node(Host(edge))
            elif edge['type'] == 'file':
                yield Node(FileHash(edge))
            elif edge['type'] == 'cidr':
                yield Node(Cidr(edge))
            elif edge['type'] == 'asn':
                yield Node(Asn(edge))
