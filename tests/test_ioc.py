import pytest
from seclytics.ioc import Ioc
from seclytics import Seclytics


class TestAsnInfo():

    def test_empty_data(self):
        data = {}
        client = Seclytics(access_token='')
        ioc = Ioc(client, data)
        assert ioc.categories == []

    def test_prediction(self):
        categories = {u'source1': [u'category1']}
        data = {
            u'context':{u'categories': categories},
            u'predictions':[
                {
                    "category": "malware", 
                    "cidr": "188.165.92.121/29", 
                    "cluster": "50241b1bd9d6559dce2c38c7ea83d5b44b67961b", 
                    "predicted_at": "2014-04-01T01:00:00"
                }
            ]
        }
        client = Seclytics(access_token='')
        ioc = Ioc(client, data)
        assert len(ioc.predictions) == 1
        assert ioc.predicted
    

    def test_ioc_categories(self):
        categories = {u'source1': [u'category1']}
        data = {u'context':{u'categories': categories}}
        client = Seclytics(access_token='')
        ioc = Ioc(client, data)
        assert ioc.categories == [u'category1']
