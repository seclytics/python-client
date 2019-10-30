from hashlib import sha1
import six
import requests
from .exceptions import InvalidAccessToken, OverQuota, ApiError
from .ioc import Ip, Cidr, Asn, Host, FileHash, Domain, Url
from . import __version__
from .node import Node

try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse


class Seclytics(object):
    """Main Module for calling the Seclytics API

    Attributes:
        access_token (str): Seclytics Access Token
        base_url (str): API URL
        session (Session): requests session
    """
    def __init__(self, access_token,
                 api_url='https://api.seclytics.com',
                 session=None):
        self.access_token = access_token
        self.base_url = api_url
        self.session = session
        if not self.session:
            self.session = requests.Session()


        # set User-Agent to make notifying of new builds easier
        client_user_agent = 'seclytics-python-client/{}'.format(
            __version__.__version__
        )
        default_headers = {
            'User-Agent': client_user_agent,
            'Authorization': "Bearer {}".format(access_token)
        }
        self.session.headers.update(default_headers)
        self.mount_ioc_lookups()

    def _get_request(self, path, params):
        """Perform GET request for path and params

        Handles API errors

        Args:
            path (str): the api path
            params (str): api params
        """
        url = ''.join((self.base_url, path))
        # convert attributes to a comma delimited list
        for (field, value) in six.iteritems(params):
            if isinstance(value, (list, set)):
                params[field] = ','.join(value)
        response = self.session.get(url, params=params)
        print(response.json())
        self._check_response_for_errors(response)
        data = response.json()
        return data

    @staticmethod
    def _check_response_for_errors(response):
        if response.status_code == 401:
            raise InvalidAccessToken()
        if response.status_code == 429:
            raise OverQuota()
        if response.status_code != 200:
            msg = "Non 200 Response"
            if response.text:
                msg = response.text
            raise ApiError(msg)

    def _post_data(self, path, params, data=None):
        url = ''.join([self.base_url, path])
        response = self.session.post(url, params=params, json=data)
        self._check_response_for_errors(response)
        data = response.json()
        return data

    def _ioc_show(self, ioc_path, ioc_id, fields=None):
        path = '/%s/%s' % (ioc_path, ioc_id)
        params = {}
        if fields:
            params['fields'] = fields
        response = self._get_request(path, params)
        if 'error' in response:
            return RuntimeError(response['error']['message'])
        return Node.build_for_row(self, response)

    def _ioc_index(self, ioc_path, iocs, fields=None):
        path = '/%s/' % ioc_path
        params = {'ids': iocs}
        if fields:
            params['fields'] = fields
        response = self._get_request(path, params)
        if 'data' not in response:
            return

        for row in response['data']:
            yield Node.build_for_row(self, row)

    def bulk_api_download(self, name, data_dir=None):
        filename = name
        if data_dir:
            filename = '/'.join([data_dir, filename])
        path = '/bulk/%s' % name
        url = ''.join((self.base_url, path))
        response = self.session.get(url, stream=True)
        self._check_response_for_errors(response)

        with open(filename, 'wb') as file_handle:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    file_handle.write(chunk)
        return filename

    def _single_ioc_wrapper(self, endpoint):
        def mounted_method(ioc, **kwargs):
            return self._ioc_show(endpoint, ioc, **kwargs)
        return mounted_method

    def _multiple_iocs_wrapper(self, endpoint):
        def mounted_method(iocs, **kwargs):
            return self._ioc_index(endpoint, iocs, **kwargs)
        return mounted_method

    def mount_ioc_lookups(self):
        single_iocs = [
            ('ip', 'ips'),
            ('cidr', 'cidrs'),
            ('asn', 'asns'),
            ('host', 'hosts'),
            ('file', 'files'),
            ('domain', 'domains'),
        ]
        for (method_name, endpoint) in single_iocs:
            assert method_name != endpoint
            setattr(self, method_name, self._single_ioc_wrapper(endpoint))
            setattr(self, endpoint, self._multiple_iocs_wrapper(endpoint))

    def urls(self, urls, fields=None):
        path = '/urls/hash'
        params = {'fields': fields}
        data = {'urls': urls}
        response = self._post_data(path, params, data)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node.build_for_row(self, row)

    def hashed_urls(self, iocs, **kwargs):
        hashed_urls = set()
        for url in iocs:
            parsed = urlparse(url.strip())
            if not parsed.hostname:
                continue
            hashed_path = None
            hashed_query = None
            if six.PY2:
                hashed_path = sha1(parsed.path).hexdigest()
                hashed_query = sha1(parsed.query).hexdigest()
            else:
                hashed_path = sha1(parsed.path.encode('utf8')).hexdigest()
                hashed_query = sha1(parsed.query.encode('utf8')).hexdigest()

            hashed_url = '/'.join((parsed.hostname, hashed_path,
                                   hashed_query))
            hashed_urls.add(hashed_url)
        return self._ioc_index('urls', hashed_urls, **kwargs)

    def hosts_live_dns(self, hosts, fields=None):
        path = '/hosts/live_dns/'
        params = {'ids': hosts}
        if fields:
            params['attributes'] = fields
        response = self._get_request(path, params)
        return response

    def cidr_ips(self, cidr, fields=None):
        path = u'/cidrs/{}/ips/'.format(cidr)
        params = {}
        if fields:
            params[u'attributes'] = fields
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node.build_for_row(self, row)
