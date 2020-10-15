# feed-to-csp
BloxOne Threat Defense integration with Fortinet, Palo Alto and Cyber threat coalition domain names and IPs brings an even wider IOC coverage by threat intelligence unification. Third party IOCs are enforced at DNS level globally on all DNS even for roaming users who have not established their VPN


## Feed integration:

* 1-feed-to-db.py

Download Fortinet/ Palo Alto / TIDE IOCs

* 2-age-db.py

Age list by removing older than X days IOCs

* 3-dedup-iocs-to-db.py

Build list of deduplicated IOCs and write to db

* 4-push-to-csp.py

downloads third party vendor named_lists from csp.infoblox.com
removes entries from csp.infoblox.com that are not anymore in the list of new IOCs
creates new named_lists if capacity requires it
adds entries from the list of new IOCS to the named_lists

## Farsight Newly Observed Domains analysis:

* a-analyze-db.py

Determine overlap and Build Venn diagram

* b-farsight-time-gained.py

Determine IOCs confirmed by security vendors and time gained by Farsight NOD

* c-notable-timelines.py

Build timelines for IOCs confirmed by more than 3 security vendors to highlight time gained by Farsight NOD


## Backtesting Farsight NOD hits from BloxOne Threat Defense

* d-farsight-time-gained-backtest.py

Determine IOCs confirmed by security vendors from NOD actual hit

* e-notable-timeline-backtest.py

Build timelines for IOCs confirmed by security vendors from NOD actual hits


## Installation:

Modify fortinet, palo alto, tide and csp api keys and palo alto url in the config.yml file

Modify the data you want to see in the Venn Diagram (up to 6 - 4 recommended for optimal readability) by commenting / uncommenting line 57-72
