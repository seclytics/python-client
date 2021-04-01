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
    def __init__(self, malicious_path=None, has_intel_path=None,
                 predicted_path=None):
        self.malicious = PortableBloom(malicious_path)\
                if malicious_path else None
        self.predicted = PortableBloom(predicted_path)\
                if predicted_path else None
        self.has_intel = PortableBloom(has_intel_path)\
                if has_intel_path else None

    def check_ip(self, ip_addr, check_suspicious=True, check_predicted=True,
                 check_malicious=True):
        """Compare the IP against all the bloom filters

        To reduce bloom filter checks we store ALL ips in has_intel
        This way the majority of IPs will only have to check once.
        """
        value = self.format_ip(ip_addr)

        # Requires all 3 bloom filters
        if not (self.malicious and self.predicted and self.has_intel):
            raise Exception("Missing bloom filter, please download"
                    " all bloom filters.")

        if self.has_intel.contains(value):
            if check_predicted and self.predicted.contains(value):
                return Category.predicted
            if check_malicious and self.malicious.contains(value):
                return Category.malicious
            if check_suspicious:
                return Category.suspicious
        return None

    def check_predicted(self, ip_addr):
        """Check if IP is predicted."""
        if not self.predicted:
            raise Exception("Missing predicted ip bloom filter.")
        value = self.format_ip(ip_addr)
        if self.predicted.contains(value):
            return Category.predicted
        return None

    def check_malicious(self, ip_addr):
        """Check if IP is malicious."""
        if not self.malicious:
            raise Exception("Missing malicious ip bloom filter.")
        value = self.format_ip(ip_addr)
        if self.malicious.contains(value):
            return Category.malicious
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
