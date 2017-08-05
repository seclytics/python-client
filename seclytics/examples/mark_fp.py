from .. import Seclytics
from optparse import OptionParser
from texttable import Texttable
from pprint import pprint

if __name__ == '__main__':
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

    # Set the attributes you want
    # https://dashboard.seclytics.com/docs#Attributes
    attributes = ['connections', 'predictions', 'passive_dns']

    # Record Threat Data (false negative)
    ip = '218.255.67.239'
    report = client.ip(ip, attributes=attributes)
    status = report.record_threat_data(reason="Looks like locky")
    pprint(report.intel)
    print(status)

    # Record Benign IOC (false positive)
    ip = '8.8.8.8'
    report = client.ip(ip, attributes=attributes)
    status = report.mark_as_good(reason="Google DNS")
    pprint(report.intel)
    print(status)
