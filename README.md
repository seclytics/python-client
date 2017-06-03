# Seclytics API Python Client 

Python module for interacting with the Seclytics API.

## Installation

pip install git+git://github.com/seclytics/python-client

## Usage

```python
from seclytics import Seclytics
access_token = 'YOUR_TOKEN'

client = Seclytics(access_token=access_token)

# get IP info
report = client.ip('89.32.40.238')

```
