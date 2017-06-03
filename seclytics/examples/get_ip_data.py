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
    (options, args) = parser.parse_args()

    if options.access_token is None:
        parser.error('access_token not given')

    # initialize the client with your token
    access_token = options.access_token
    client = Seclytics(access_token=access_token)

    # Set the attributes you want
    # https://dashboard.seclytics.com/docs#Attributes
    attributes = ['connections', 'predictions', 'passive_dns']

    # Request the threat intel
    ip = '80.82.67.191'
    report = client.ip(ip, attributes=attributes)

    # Who reported this?
    print("Reported By", report.reported_by)

    # What IOCs are connected
    print("\n\nConnected IOCs\n\n")
    table = Texttable(max_width=0)
    table.set_deco(Texttable.HEADER)
    table.set_cols_dtype(['t', 't', 't', 't'])
    table.header(["ioc_type", "ioc", "categories", "identifiers"])
    for connection in report.connections:
        table.add_row([
            connection.ioc_type,
            connection.ioc_id,
            ','.join(connection.categories),
            ','.join(connection.identifiers)
            ])
    print(table.draw())

    # The raw JSON reponse is available via the intel attribute
    print("JSON Response")
    pprint(report.intel)
