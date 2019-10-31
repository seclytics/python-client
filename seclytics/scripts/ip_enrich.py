#!/usr/bin/env python
from optparse import OptionParser
import sys
import json
from .. import Seclytics
from .file_input import FileInput


def get_options():
    """Get commandline options"""
    parser = OptionParser()
    parser.add_option("--access_token",
                      action="store", type="string", dest="access_token",
                      help="API acccess_token")
    parser.add_option("--api_url",
                      action="store", type="string", dest="api_url",
                      default='https://api.seclytics.com/',
                      help="API Hostname")
    (options, _) = parser.parse_args()
    if options.access_token is None:
        parser.error('access_token not given')
    return options


def main():
    options = get_options()
    # initialize the client with your token
    access_token = options.access_token
    api_url = options.api_url
    client = Seclytics(access_token, api_url=api_url)

    def process_batch(ips):
        for node in client.ips(ips):
            print(json.dumps(node.intel))

    batch = set()
    with FileInput(sys.stdin) as file_handle:
        for line in file_handle:
            batch.add(line.strip())
            if len(batch) >= 50:
                process_batch(batch)
                batch = set()
    if batch:
        process_batch(batch)


if __name__ == '__main__':
    main()
