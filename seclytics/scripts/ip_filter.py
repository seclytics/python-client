#!/usr/bin/env python
from .. import Seclytics
from ..portable_bloom import PortableBloom
from ..bloom_category import BloomCategory, Category
from optparse import OptionParser
import sys


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
    parser.add_option("--data-dir", default='/tmp',
                      action="store", type="string", dest="data_dir",
                      help="Directory where DBs exist")
    parser.add_option("--malicious",
                      action="store_true", default=False, dest="malicious",
                      help="Allow malicious")
    parser.add_option("--suspicious",
                      action="store_true", default=False, dest="suspicious",
                      help="Allow suspicious")
    parser.add_option("--predicted",
                      action="store_true", default=False, dest="predicted",
                      help="Allow predicted")
    (options, args) = parser.parse_args()

    if(not options.malicious and
       not options.predicted and
       not options.suspicious):
        parser.error("Please specify at least one category")

    bloom = BloomCategory(malicious_path='/tmp/malicious-ips.bloom',
                          predicted_path='/tmp/predicted-ips.bloom',
                          has_intel_path='/tmp/ip-threat-intel.bloom')
    with FileInput(sys.stdin) as f:
        for line in f:
            ip = line.strip()
            if bloom.check_ip(ip, check_malicious=options.malicious,
                              check_predicted=options.predicted,
                              check_suspicious=options.suspicious):
                print(ip)


if __name__ == '__main__':
    main()
