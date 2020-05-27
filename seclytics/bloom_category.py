#!/usr/bin/env python
"""Determine the category of an IP using the three bloom filters

Bloom filters provide a way to limit your requests the API. If you get
a match then check the API for an authorative response.
"""

import sys
from enum import Enum
import ipaddress
from .portable_bloom import PortableBloom


class Category(Enum):
    """Use an enum to map the categories"""
    malicious = 1
    predicted = 2
    suspicious = 3


class BloomCategory(object):
    """Loads the three bloomfilters and provides a way to check ips
    """
    def __init__(self, malicious_path, has_intel_path, predicted_path):
        self.malicious = PortableBloom(malicious_path)
        self.predicted = PortableBloom(predicted_path)
        self.has_intel = PortableBloom(has_intel_path)

    def check_ip(self, ip_addr, check_suspicious=True, check_predicted=True,
                 check_malicious=True):
        """Compare the IP against all the bloom filters

        To reduce bloom filter checks we store ALL ips in has_intel
        This way the majority of IPs will only have to check once.
        """
        value = self.format_ip(ip_addr)

        if self.has_intel.contains(value):
            if check_predicted and self.predicted.contains(value):
                return Category.predicted
            if check_malicious and self.malicious.contains(value):
                return Category.malicious
            if check_suspicious:
                return Category.suspicious
        return None

    @staticmethod
    def format_ip(value):
        """Format the IP before sending to bloom

        Parameters:
            value: the ip in int or dot notation

        Returns (str) IP address in dot notation
        """
        if not isinstance(value, str) and sys.version_info < (3, 0):
            raise RuntimeError("Only accepts str")

        if isinstance(value, str) and value.isdigit():
            # map int ip to dot notation
            return str(ipaddress.IPv4Address(int(value)))

        return value
