import sys
from tempfile import NamedTemporaryFile
import ipaddress
import pytest
from seclytics.bloom_category import BloomCategory
from pybloomfilter import BloomFilter


@pytest.fixture(scope="module")
def malicious_ips():
    """Known malicious IPs"""
    return set(['1.1.1.1',  # only malicious
                '2.2.2.2',  # malicious and predicted
                '3.3.3.3'])


@pytest.fixture(scope="module")
def predicted_ips():
    """Known predicted IPs"""
    return set(['2.2.2.2',  # malicious and predicted
                '4.4.4.4'])  # only predicted


@pytest.fixture(scope="module")
def all_ips():
    """All IPs"""
    return set(['1.1.1.1', '2.2.2.2', '3.3.3.3',
                '4.4.4.4'])


@pytest.fixture(scope="module")
def bloom_filters(all_ips, predicted_ips, malicious_ips):
    """Create temp bloom filters for testing"""
    malicious_path = NamedTemporaryFile(delete=False).name

    malicious = BloomFilter(100000, 0.1, malicious_path)
    malicious.update(malicious_ips)

    has_intel_path = NamedTemporaryFile(delete=False).name
    has_intel = BloomFilter(100000, 0.1, has_intel_path)
    has_intel.update(all_ips)

    predicted_path = NamedTemporaryFile(delete=False).name
    predicted = BloomFilter(100000, 0.1, predicted_path)
    predicted.update(predicted_ips)
    return (malicious_path, has_intel_path, predicted_path)


class TestBloomCategory(object):
    def test_ip(self, bloom_filters, malicious_ips, predicted_ips, all_ips):
        """Make sure we can query the bloom filters by IP"""
        # malicious_path, has_intel_path, predicted_path
        category = BloomCategory(*bloom_filters)
        # check known good ip
        assert not category.check_ip('8.8.8.8')
        # check known good int ip
        assert not category.check_ip('8888')

        # make sure all our IPs are in the bloom
        for ip_addr in malicious_ips:
            assert category.check_ip(ip_addr)
            assert category.check_malicious(ip_addr)
        for ip_addr in all_ips:
            assert category.check_ip(ip_addr)
        for ip_addr in predicted_ips:
            assert category.check_ip(ip_addr)
            assert category.check_predicted(ip_addr)
            ip_digit = None
            if sys.version_info < (3, 0):
                ip_digit = str(int(ipaddress.IPv4Address(unicode(ip_addr))))
            else:
                ip_digit = str(int(ipaddress.IPv4Address(ip_addr)))
            assert category.check_ip(ip_digit)
            assert category.check_predicted(ip_digit)
