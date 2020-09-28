# feed-to-csp
BloxOne Threat Defense integration with Fortinet and Palo Alto domain names and IPs brings an even wider IOC coverage by threat intelligence unification. Third party IOCs are enforced at DNS level globally on all DNS even for roaming users who have not established their VPN


## 5 python scripts:

* 1)feed-to-db.py

Download Fortinet/ Palo Alto / TIDE IOCs

* 2)age-db.py

Age list by removing older than X days IOCs

* 3)analyze-db.py

Determine overlap and Build Venn diagram

* 4)dedup-iocs-to-db.py

Build list of deduplicated IOCs and write to db

* 5)push-to-csp.py

downloads all Fortiguard_* named_lists from csp.infoblox.com
removes entries from csp.infoblox.com that are not anymore in the list of new IOCs
creates new named_lists if capacity requires it
adds entries from the list of new IOCS to the named_lists



## Installation:

Modify api keys and palo alto url in the config.yml file 
