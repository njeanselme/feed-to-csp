# feed-to-csp
BloxOne Threat Defense integration with Fortinet and Palo Alto domain names and IPs brings an even wider IOC coverage by threat intelligence unification. Third party IOCs are enforced at DNS level globally on all DNS even for roaming users who have not established their VPN


5 python scripts:

1)feed-to-db.py

Download Fortinet/ Palo Alto / TIDE IOCs

2)age-db.py

Age list by removing older than X days IOCs

3)analyze-db.py

Determine overlap and Build Venn diagram

4)dedup-iocs-to-db.py

Build list of deduplicated IOCs and write to db

5)push-to-csp.py

downloads all Fortiguard_* named_lists from csp.infoblox.com
removes entries from csp.infoblox.com that are not anymore in the list of new IOCs
creates new named_lists if capacity requires it
adds entries from the list of new IOCS to the named_lists



Installation:

Modify api keys and palo alto url in the config.yml file 

csp_apikey: 1111111111111111111111111111111f


tide_apikey: 111111111111111111111111111111111111111111111111111111111111111f

tide_hosts_url: https://api.activetrust.net/api/data/threats/state/host?period=24h&data_format=ndjson

tide_ips_url: https://api.activetrust.net/api/data/threats/state/IP?period=24h&data_format=ndjson

fortiguard_apikey: 111111111111111111111111111111111111111111111111111111111111111f

fortiguard_url: https://premiumapi.fortinet.com/v1/cti/feed/stix?cc=all

paloalto_autofocus_apikey: 1111111f-111f-111f-111f-11111111111f

paloalto_autofocus_url: https://autofocus.paloaltonetworks.com/api/v1.0/IOCFeed/1111111111111111111111111111111f/MalwareDNS


age_IOCs_inactive_for_days: 30
use_already_downloaded_IOC_files: False
