#!/usr/bin/env python
from .. import Seclytics
from ..portable_bloom import PortableBloom
from ..bloom_category import BloomCategory, Category
from optparse import OptionParser
import sys
import json


class FileInput(object):
    def __init__(self, file):
        self.file = file

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.file.close()

    def __iter__(self):
        return self

    def next(self):
        line = self.file.readline()

        if line is None or line == "":
            raise StopIteration

        return line


def main():
    # pass in the access_token via commandline
    parser = OptionParser()
    parser.add_option("--access_token",
                      action="store", type="string", dest="access_token",
                      help="API acccess_token")
    parser.add_option("--api_url",
                      action="store", type="string", dest="api_url",
                      default='https://api.seclytics.com/',
                      help="API Hostname")
    (options, args) = parser.parse_args()
    if options.access_token is None:
        parser.error('access_token not given')

    # initialize the client with your token
    access_token = options.access_token
    api_url = options.api_url
    client = Seclytics(access_token=access_token, api_url=api_url)

    batch = set()
    with FileInput(sys.stdin) as f:
        for line in f:
            ip = line.strip()
            batch.add(ip)
            if len(batch) >= 50:
                r = client._get_request('ips', {'ids': batch})
                for row in r['data']:
                    print(json.dumps(row))
                batch = set()
    if len(batch) > 0:
        r = client._get_request('ips', {'ids': batch})
        for row in r['data']:
            print(json.dumps(row))


if __name__ == '__main__':
    main()
