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
        if not self.check_has_intel(ip_addr):
            return None
        if check_predicted and self.check_predicted(ip_addr):
            return Category.predicted
        if check_malicious and self.check_malicious(ip_addr):
            return Category.malicious
        if check_suspicious:
            return Category.suspicious
        return None

    def check_has_intel(self, ip_addr):
        """Check if IP is predicted."""
        if not self.has_intel:
            raise Exception("Missing required threat intel bloom filter.")
        value = self.format_ip(ip_addr)
        return self.has_intel.contains(value)

    def check_predicted(self, ip_addr):
        """Check if IP is predicted."""
        return self.check_on_bloom(Category.predicted, ip_addr)

    def check_malicious(self, ip_addr):
        """Check if IP is malicious."""
        return self.check_on_bloom(Category.malicious, ip_addr)

    def check_on_bloom(self, category, ip_addr):
        """Check on either malicious or predicted ip bloom."""
        if category == Category.malicious:
            bloom = self.malicious
        elif category == Category.predicted:
            bloom = self.predicted
        if not bloom:
            raise Exception("Missing required bloom filter.")
        value = self.format_ip(ip_addr)
        if bloom.contains(value):
            return category
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
