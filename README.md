# Seclytics API Python Client 

Python module for interacting with the Seclytics API.

## Installation

```bash
pip install git+git://github.com/seclytics/python-client.git --upgrade
```


## Usage

```python
from seclytics import Seclytics
access_token = 'YOUR_TOKEN'

client = Seclytics(access_token=access_token)

# get IP info
report = client.ip('89.32.40.238')

# check if predicted
if report.predicted:
  print(report.predictions)

# get passive dns
report.passive_dns

```

## Bloom Filter Usage

**Requires Access To Our Bloom Filters**

### Download the bloom filters

```bash
python -m seclytics.scripts.download_db --access_token YOUR_ACCESS_TOKEN --name predicted-ips.bloom,malicious-ips.bloom,ip-threat-intel.bloom --data-dir /tmp
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
curl http://www.malwaredomainlist.com/hostslist/ip.txt 2> /dev/null | python -m seclytics.scripts.ip_filter --predicted | python -m seclytics.scripts.ip_enrich --access_token YOUR_ACCESS_TOKEN | jq .context.source_urls
```

## TODO

* Add documentation
* Add more tests
* Add methods for multiple IOC lookups 
* Wrap passive dns results with object
* Wrap prediction with object
* Create CLI app
