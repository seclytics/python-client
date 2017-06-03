import pytest
from seclytics.ioc import Ioc


class TestAsnInfo():

    def test_empty_data(self):
        data = {}
        ioc = Ioc(data)
        assert ioc.categories == []

    def test_ioc_categories(self):
        categories = {u'source1': [u'category1']}
        data = {u'context':{u'categories': categories}}
        ioc = Ioc(data)
        assert ioc.categories == [u'category1']
