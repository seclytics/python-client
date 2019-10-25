#!/usr/bin/env python
"""Sample script that uses BloomFilters to filter out IPs before calling
the API.

echo '51.255.139.200' | python -m seclytics.scripts.ip_filter --suspicious --malicious --predicted
"""
from optparse import OptionParser
import sys
from ..bloom_category import BloomCategory
from .file_input import FileInput


def get_options():
    """Parse the command line options"""
    # pass in the access_token via commandline
    parser = OptionParser()
    parser.add_option("--data-dir", default='/tmp',
                      action="store", type="string", dest="data_dir",
                      help="Directory where DBs exist")
    parser.add_option("--malicious",
                      action="store_true", default=False, dest="malicious",
                      help="Check malicious")
    parser.add_option("--suspicious",
                      action="store_true", default=False, dest="suspicious",
                      help="Check suspicious")
    parser.add_option("--predicted",
                      action="store_true", default=False, dest="predicted",
                      help="Check predicted")
    (options, _) = parser.parse_args()
    if(not options.malicious and
       not options.predicted and
       not options.suspicious):
        parser.error("Please specify at least one category")


    return options

def main():
    """Using the options and stdin check the bloom filters for IOCs"""
    options = get_options()
    data_path = str(options.data_dir)
    bloom = BloomCategory(malicious_path=data_path + '/malicious-ips.bloom',
                          predicted_path=data_path + '/predicted-ips.bloom',
                          has_intel_path=data_path + '/ip-threat-intel.bloom')
    with FileInput(sys.stdin) as file_handle:
        for line in file_handle:
            ip_address = line.strip()
            if bloom.check_ip(ip_address,
                              check_malicious=options.malicious,
                              check_predicted=options.predicted,
                              check_suspicious=options.suspicious):
                print(ip_address)


if __name__ == '__main__':
    main()
