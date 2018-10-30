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
        if self.has_intel.contains(ip):
            if check_malicious and self.malicious.contains(ip):
                return Category.malicious
            if check_predicted and self.predicted.contains(ip):
                return Category.predicted
            if check_suspicious:
                return Category.suspicious
