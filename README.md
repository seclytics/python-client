# Seclytics API Python Client 

Python module for interacting with the Seclytics API.

## Installation for python 2.7

```bash
pip install enum pybloomfiltermmap
pip install git+git://github.com/seclytics/python-client.git --upgrade
```

## Installation for python 3.7 - 3.12

```bash
pip install cython
pip install pybloomfiltermmap3
pip install git+https://github.com/seclytics/python-client.git --upgrade
```


## Usage

```python
from seclytics import Seclytics
access_token = 'YOUR_ACCESS_TOKEN'

client = Seclytics(access_token=access_token)

# get IP info
report = client.ip('89.32.40.238')

# check if predicted
if report.predicted:
  print(report.predictions)

# get passive dns
report.passive_dns

```

## Usage with proxy

Set the proxy using the requests session.

```python
import requests
from seclytics import Seclytics

session = requests.Session()
session.proxies = {'http': 'http://proxy', 'https': 'https://proxy'}
access_token = 'YOUR_ACCESS_TOKEN'

client = Seclytics(access_token=access_token, session=session)
```


## Bloom Filter Usage

**Requires Access To Our Bloom Filters**

### Download the bloom filters

```bash
export SECLYTICS_ACCESS_TOKEN="YOUR_ACCESS_TOKEN"
python -m seclytics.scripts.download_db --access_token $SECLYTICS_ACCESS_TOKEN --name predicted-ips.bloom,malicious-ips.bloom,ip-threat-intel.bloom --data-dir /tmp
```

### Command Line Filter Examples

Reads data from STDIN and only prints if it matches on the specified flags

```bash
$ echo '139.47.251.221' | python -m seclytics.scripts.ip_filter --suspicious --malicious --predicted
> 139.47.251.221
```

IP that's malicious but not predicted (outputs nothing)

```bash
$ echo '91.195.240.82' | python -m seclytics.scripts.ip_filter --predicted
> 
```

Malicious IP

```bash
$ echo '91.195.240.82' | python -m seclytics.scripts.ip_filter --malicious
> 91.195.240.82
```

Check if we have any info this ip 

```bash
$ echo '51.255.139.200' | python -m seclytics.scripts.ip_filter --suspicious --malicious --predicted
> 51.255.139.200
```

Finding predicted IPs in a list of IPs.

```bash
$ curl http://www.malwaredomainlist.com/hostslist/ip.txt 2> /dev/null | python -m seclytics.scripts.ip_filter --predicted 
```

Using bloom filter to filter before querying API for more info

```bash
export SECLYTICS_ACCESS_TOKEN="YOUR_ACCESS_TOKEN"
curl http://www.malwaredomainlist.com/hostslist/ip.txt 2> /dev/null | python -m seclytics.scripts.ip_filter --predicted | python -m seclytics.scripts.ip_enrich --access_token $SECLYTICS_ACCESS_TOKEN | jq .context.source_urls
```

## TODO

* Add documentation
* Add more tests
* Add methods for multiple IOC lookups 
* Wrap passive dns results with object
* Wrap prediction with object
* Create CLI app
