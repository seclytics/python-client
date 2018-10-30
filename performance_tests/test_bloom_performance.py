from random import getrandbits
from ipaddress import IPv4Address
from seclytics.bloom_category import BloomCategory


run_count = 1000000
ips = list()

for i in range(0, run_count):
    # 153,099 random ips generated per second
    bits = getrandbits(32)
    addr = str(IPv4Address(bits))
    ips.append(addr)

bloom = BloomCategory(malicious_path='/tmp/malicious-ips.bloom',
                      predicted_path='/tmp/predicted-ips.bloom',
                      has_intel_path='/tmp/ip-threat-intel.bloom')


def test():
    for ip in ips:
        bloom.check_ip(ip)
    # benchmark(bulk_features_pandas_ip_metadata, ips)


if __name__ == '__main__':
    import timeit
    test()
    time = timeit.timeit("test()", setup="from __main__ import test", number=1)
    print(run_count/time)
