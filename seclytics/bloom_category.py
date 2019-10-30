#!/usr/bin/env python
from .portable_bloom import PortableBloom
from enum import Enum



class Category(Enum):
    malicious = 1
    predicted = 2
    suspicious = 3


class BloomCategory(object):
    def __init__(self, malicious_path, has_intel_path, predicted_path):
        self.malicious = PortableBloom(malicious_path)
        self.predicted = PortableBloom(predicted_path)
        self.has_intel = PortableBloom(has_intel_path)

    def check_ip(self, ip, check_suspicious=True, check_predicted=True,
                 check_malicious=True):
        value = ip
        if type(value) != str and six.PY2:
            raise RuntimeError("Only accepts str")

        # To reduce bloom filter checks we store ALL ips in has_intel
        # This way the majority of IPs will only have to check once.
        if self.has_intel.contains(value):
            if check_predicted and self.predicted.contains(value):
                return Category.predicted
            elif check_malicious and self.malicious.contains(value):
                return Category.malicious
            elif check_suspicious:
                return Category.suspicious
