import requests
from urlparse import urlparse
from hashlib import sha1
from .exceptions import InvalidAccessToken, OverQuota, ApiError
from .ioc import Ip, Cidr, Asn, Host, FileHash, Domain, Url


class Seclytics(object):
    def __init__(self, access_token, api_url=None, verify_ssl=False, http_proxy=None):
        self.base_url = api_url or 'https://api.seclytics.com'
        self.access_token = access_token
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.proxies = {'http': http_proxy, 'https': http_proxy}

    def _get_request(self, path, params):
        url = ''.join((self.base_url, path))
        data = None
        params[u'access_token'] = self.access_token
        if 'attributes' in params:
            params[u'attributes'] = ','.join(params[u'attributes'])
        if u'ids' in params:
            if(type(params[u'ids']) == list or type(params[u'ids']) == set):
                params[u'ids'] = ','.join(params[u'ids'])
        response = self.session.get(url, params=params)
        if response.status_code == 401:
            raise InvalidAccessToken()
        elif response.status_code == 429:
            raise OverQuota()
        elif response.status_code != 200:
            msg = "Non 200 Response"
            if response.text:
                msg = response.text
            raise ApiError(msg)
        data = response.json()
        return data

    def _post_data(self, path, data={}):
        url = ''.join((self.base_url, path))
        params = {u'access_token': self.access_token}
        response = self.session.post(url, params=params, json=data)
        if response.status_code == 401:
            raise InvalidAccessToken()
        elif response.status_code == 429:
            raise OverQuota()
        elif response.status_code != 200:
            msg = "Non 200 Response"
            if response.text:
                msg = response.text
            raise ApiError(msg)
        data = response.json()
        return data

    def _ioc_show(self, ioc_path, ioc_id, attributes=None):
        path = u'/%s/%s' % (ioc_path, ioc_id)
        params = {}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'error' in response:
            return RuntimeError(response['error']['message'])
        return response

    def bulk_api_download(self, name, data_dir=None):
        params = {u'access_token': self.access_token}
        filename = name
        if data_dir is not None:
            filename = '/'.join([data_dir, filename])
        path = '/bulk/%s' % name
        url = ''.join((self.base_url, path))
        response = self.session.get(url, params=params, stream=True)

        if response.status_code == 401:
            raise InvalidAccessToken()
        elif response.status_code == 429:
            raise OverQuota()
        elif response.status_code != 200:
            raise RuntimeError(response.status)

        with open(filename, 'wb') as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
        return filename

    def ip(self, ip, attributes=None):
        response = self._ioc_show('ips', ip, attributes=attributes)
        return Node(Ip(self, response))

    def cidr(self, cidr, attributes=None):
        response = self._ioc_show('cidrs', cidr, attributes=attributes)
        return Node(Cidr(self, response))

    def asn(self, asn, attributes=None):
        response = self._ioc_show('asns', asn, attributes=attributes)
        return Node(Asn(self, response))

    def host(self, host, attributes=None):
        response = self._ioc_show('hosts', host, attributes=attributes)
        return Node(Host(self, response))

    def file(self, file_hash, attributes=None):
        response = self._ioc_show('files', file_hash, attributes=attributes)
        return Node(FileHash(self, response))

    def domain(self, domain, attributes=None):
        response = self._ioc_show('domains', domain, attributes=attributes)
        return Node(Domain(self, response))

    def ips(self, ips, attributes=None):
        path = u'/ips/'
        params = {u'ids': ips}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node(Ip(self, row))

    def hosts(self, ips, attributes=None):
        path = u'/hosts/'
        params = {u'ids': ips}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node(Host(self, row))

    def cidrs(self, cidrs, attributes=None):
        path = u'/cidrs/'
        params = {u'ids': cidrs}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node(Cidr(self, row))

    def domains(self, domains, attributes=None):
        path = u'/domains/'
        params = {u'ids': domains}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node(Domain(self, row))

    def files(self, files, attributes=None):
        path = u'/files/'
        params = {u'ids': files}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node(FileHash(self, row))

    def urls(self, urls, attributes=None):
        path = u'/urls/'
        ids = str()
        for url in urls.split(','):
            parsed = urlparse(url.strip())
            hashed_path = sha1(parsed.path).hexdigest()
            hashed_query = sha1(parsed.query).hexdigest()
            ids += "{}/{}/{},".format(parsed.hostname, hashed_path, hashed_query)
        params = {u'ids': ids}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node(Url(self, row))

    def asns(self, asns, attributes=None):
        path = u'/asns/'
        params = {u'ids': asns}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node(Asn(self, row))

    def ips_to_host(self, hosts, attributes=None):
        path = u'/hosts/live_dns/'
        params = {u'ids': hosts}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        return response

    def cidr_ips(self, cidr, attributes=None):
        path = u'/cidrs/{}/ips/'.format(cidr)
        params = {}
        if attributes:
            params[u'attributes'] = attributes
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node(Ip(self, row))


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
                yield Node(Ip(self, edge))
            elif edge['type'] == 'host':
                yield Node(Host(self, edge))
            elif edge['type'] == 'file':
                yield Node(FileHash(self, edge))
            elif edge['type'] == 'cidr':
                yield Node(Cidr(self, edge))
            elif edge['type'] == 'asn':
                yield Node(Asn(self, edge))
