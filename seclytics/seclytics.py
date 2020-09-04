"""Main seclytics endpoint."""
from hashlib import sha1
import sys
import os
import requests
from .exceptions import InvalidAccessToken, OverQuota, ApiError
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

        # setup the session
        # allow users to pass in a session for proxy support
        self.session = session
        if not self.session:
            self.session = requests.Session()
        self.session.headers.update(self.default_headers)
        self.mount_ioc_lookups()

    @property
    def default_headers(self):
        """Set's default headers for the API

            * User-Agent to make notifying of new builds easier
            * Authorization for auth
        """
        client_user_agent = 'seclytics-python-client/{}'.format(
            __version__.__version__
        )
        return {
            'User-Agent': client_user_agent,
            'Authorization': "Bearer {}".format(self.access_token)
        }

    def _get_request(self, path, params):
        """Perform GET request for path and params

        Handles API errors

        Args:
            path (str): the api path
            params (str): api params
        """
        url = ''.join((self.base_url, path))
        # convert attributes to a comma delimited list
        for (field, value) in params.items():
            if isinstance(value, (list, set)):
                params[field] = ','.join(value)
        response = self.session.get(url, params=params)
        self._check_response_for_errors(response)
        data = response.json()
        return data

    @staticmethod
    def _check_response_for_errors(response):
        """Rasies an error depending on the status_code"""
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

    def bulk_api_download(self, name, data_dir='/tmp/'):
        """Download a file from the bulk api."""
        endpoint = '/bulk/' + name
        return BulkDownload(self, endpoint, data_dir).download()

    def binary_download(self, file_hash, data_dir='/tmp/'):
        """Download a binary sample."""
        endpoint = '/files/%s/download' % file_hash
        return BulkDownload(self, endpoint, data_dir).download()

    def _single_ioc_wrapper(self, endpoint):
        def mounted_method(ioc, **kwargs):
            return self._ioc_show(endpoint, ioc, **kwargs)
        return mounted_method

    def _multiple_iocs_wrapper(self, endpoint):
        def mounted_method(iocs, **kwargs):
            return self._ioc_index(endpoint, iocs, **kwargs)
        return mounted_method

    def mount_ioc_lookups(self):
        """Set the ioc lookup attributes."""
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
        """Get URL data."""
        path = '/urls/hash'
        params = {'fields': fields}
        data = {'urls': urls}
        response = self._post_data(path, params, data)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node.build_for_row(self, row)

    def hashed_urls(self, iocs, **kwargs):
        """Get URL data by hash."""
        hashed_urls = set()
        for url in iocs:
            parsed = urlparse(url.strip())
            if not parsed.hostname:
                continue
            hashed_path = None
            hashed_query = None
            if sys.version_info > (3, 0):
                hashed_path = sha1(parsed.path.encode('utf8')).hexdigest()
                hashed_query = sha1(parsed.query.encode('utf8')).hexdigest()
            else:
                hashed_path = sha1(parsed.path).hexdigest()
                hashed_query = sha1(parsed.query).hexdigest()

            hashed_url = '/'.join((parsed.hostname, hashed_path,
                                   hashed_query))
            hashed_urls.add(hashed_url)
        return self._ioc_index('urls', hashed_urls, **kwargs)

    def hosts_live_dns(self, hosts, fields=None):
        """Get live dns for hosts."""
        path = '/hosts/live_dns/'
        params = {'ids': hosts}
        if fields:
            params['attributes'] = fields
        response = self._get_request(path, params)
        return response

    def cidr_ips(self, cidr, fields=None):
        """Get all the IPs for a CIDR."""
        path = '/cidrs/{}/ips/'.format(cidr)
        params = {}
        if fields:
            params[u'attributes'] = fields
        response = self._get_request(path, params)
        if 'data' not in response:
            return
        for row in response['data']:
            yield Node.build_for_row(self, row)


class BulkDownload(object):
    """Download files from the bulk endpoint."""

    def __init__(self, api, endpoint, data_dir):
        """Create a bulk download object.

        Parameters:
            api: the seclytics API client
            endpoint: the item we want to download
            data_dir: the dir we want to download to
        """
        self.api = api
        self.endpoint = endpoint
        self.data_dir = ''
        if data_dir:
            self.data_dir = data_dir

    @property
    def filename(self):
        """Determine the file name."""
        filename = self.endpoint.replace('/', '_')
        if self.endpoint.startswith('/bulk'):
            filename = os.path.basename(self.endpoint)
        elif self.endpoint.endswith('/download'):
            filename = os.path.basename(self.endpoint[:-9])
        return os.path.join(self.data_dir, filename)

    @property
    def api_reponse(self):
        """Get the API response."""
        api_path = self.endpoint
        url = self.api.base_url + api_path
        response = self.api.session.get(url, stream=True)
        self.api._check_response_for_errors(response)
        return response

    def download(self):
        """Download API response to file."""
        response = self.api_reponse
        with open(self.filename, 'wb') as file_handle:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    file_handle.write(chunk)
        return self.filename
