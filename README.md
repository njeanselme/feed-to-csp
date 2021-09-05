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

Example output:
![Alt text](https://github.com/njeanselme/feed-to-csp/blob/master/images/Vendor%20IOC%20overlap%201.png?raw=true)


* b-farsight-time-gained.py

Determine IOCs confirmed by security vendors and time gained by Farsight NOD

Example output:
![Alt text](https://github.com/njeanselme/feed-to-csp/blob/master/images/Delay%20from%20newly%20observed%20domain%20to%20malicious%20reputation.png?raw=true)

* c-notable-timelines.py

Build timelines for IOCs confirmed by more than 3 security vendors to highlight time gained by Farsight NOD

Example output:
![Alt text](https://github.com/njeanselme/feed-to-csp/blob/master/images/detection%20timeline.png?raw=true)


## Backtesting Farsight NOD hits from BloxOne Threat Defense

* d-farsight-time-gained-backtest.py

Determine IOCs confirmed by security vendors from NOD actual hit

* e-notable-timeline-backtest.py

Build timelines for IOCs confirmed by security vendors from NOD actual hits


## Installation:

Modify fortinet, palo alto, tide and csp api keys and palo alto url in the config.yml file

Modify the data you want to see in the Venn Diagram (up to 6 - 4 recommended for optimal readability) by commenting / uncommenting line 57-72

## Automation
Once every step is tested and working as expected, you can automate the full execution with:

python3 1-feeds-to-db.py && python3 2-age-db.py && python3 3-dedup-iocs-to-db.py && python3 4-push-to-csp.py 

## Resources
Note that for a fully loaded database for 30 days of all supported vendors (SURBL, Crowdstrike, Infoblox, Farsight NOD, Fortinet, Palo Alto and Cyberthreat coalition), database takes 5GB and 3-dedup-iocs-to-db.py can take up to 48GB or memory. Tests have been done with 16GB of RAM and 32GB of swap under 30 minutes for 1-4 full process

