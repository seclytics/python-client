from pybloomfilter import BloomFilter
import os

class PortableBloom(object):
    bloom = None

    def __init__(self, path):
        if not os.path.exists(path):
            raise RuntimeError("Missing Bloom: %s" %  path)
        self.bloom = BloomFilter.open(path)

    def contains(self, value):
        return value in self.bloom
