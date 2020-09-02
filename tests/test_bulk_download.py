import pytest
import json
import requests_mock
from seclytics import Seclytics, BulkDownload
from seclytics.exceptions import InvalidAccessToken, ApiError



@pytest.fixture
def test_requests(requests_mock):
    """Session-wide test database."""
    url = 'https://api.seclytics.com/bulk/private/private_test.json'
    requests_mock.get(url, json={'name': 'private_test.json'})

    url = 'https://api.seclytics.com/bulk/test.json'
    requests_mock.get(url, json={'name': 'test.json'})

    url = 'https://api.seclytics.com/bulk/noperms.json'
    error = {
        "error": {
            "message": ("Sorry, your token does not have permissions for this "
                        "endpoint. Please contact us for additional access.")
        }
    }
    requests_mock.get(url, json=error, status_code=401)

    url = 'https://api.seclytics.com/bulk/private/missing.json' 
    error = {
        "error": {
            "message": ("404 Not Found: The requested URL was not found on the"
                        " server. If you entered the URL manually please check"
                        " your spelling and try again.")
        }
    }
    requests_mock.get(url, json=error, status_code=404)

class TestBulkDownload:
    def test_download(self, test_requests):
        """Download the file."""
        api_client = Seclytics('')
        
        file_path = api_client.bulk_api_download('test.json', '/tmp/')
        assert str(file_path) == '/tmp/test.json'
        data = json.load(file_path.open('r'))
        assert data.get('name') == 'test.json'
        
    def test_download_private(self, test_requests):
        """Download private file from bulk."""
        api_client = Seclytics('')
        file_path = api_client.bulk_api_download('private/private_test.json', '/tmp/')
        assert str(file_path) == '/tmp/private_test.json'
        data = json.load(file_path.open('r'))
        assert data.get('name') == 'private_test.json'

    def test_download_missing(self, test_requests):
        """Download private file from bulk."""
        api_client = Seclytics('')
        with pytest.raises(InvalidAccessToken):
            file_path = api_client.bulk_api_download('noperms.json', '/tmp/')
        with pytest.raises(ApiError):
            file_path = api_client.bulk_api_download('private/missing.json', '/tmp/')
