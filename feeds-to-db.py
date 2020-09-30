import requests
import base64
import json
import re
import math
import logging
import time
import datetime
import gzip
import ipaddress
import urllib
import urllib.request
import ssl
import sqlite3
#import cProfile #perf optimization only
from stix.core import STIXPackage
from cybox.core import Observables
import yaml

with open("config.yml", "r") as ymlfile:
    cfg = yaml.safe_load(ymlfile)


#########################################################	

logging.basicConfig(handlers = [logging.FileHandler('log/feed-to-db.log'), logging.StreamHandler()],level=logging.DEBUG,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

tide_apikey = cfg['tide_apikey']
tide_hosts_url = cfg['tide_hosts_url']
tide_ips_url = cfg['tide_ips_url']

fortiguard_apikey = cfg['fortiguard_apikey']
fortiguard_url = cfg['fortiguard_url']

paloalto_autofocus_apikey = cfg['paloalto_autofocus_apikey']
paloalto_autofocus_url = cfg['paloalto_autofocus_url']

cyber_threat_coalition_url = cfg['cyber_threat_coalition_url']

use_already_downloaded_IOC_files = cfg['use_already_downloaded_IOC_files']

now = datetime.datetime.utcnow().isoformat(timespec='seconds')

#########################################################

def initSQLlite():
	conn = sqlite3.connect('IOCs.db')
	logging.info('Opened database successfully')

	conn.execute('''create table if not exists iocs
         (id               text not null primary key,
         ioc               text               not null,
         provider          text               not null,
         description       text,
         first_seen        text               not null,
         last_seen         text               not null
         );''')
	logging.info('Table created successfully')

	return conn

#########################################################


def updateDB(IOC,description,provider):
	conn.execute('insert or ignore into iocs (id,ioc,provider,description,first_seen,last_seen) values ("'+IOC+provider+'","'+IOC+'","'+provider+'","'+description+'","'+now+'","'+now+'")')
	conn.execute('update iocs set last_seen = "'+now+'" where id="'+IOC+provider+'"')
	conn.commit()

#########################################################

def is_fqdn(hostname):
    """
    :param hostname: string
    :return: bool
    """
    #  Remove trailing dot
    try:  # Is this necessary?
        if hostname[-1] == '.':
            hostname = hostname[0:-1]
    except IndexError:
        return False

    #  Check total length of hostname < 253
    if len(hostname) > 253:
        return False

    #  Split hostname into list of DNS labels
    hostname = hostname.split('.')

    #  Define pattern of DNS label
    #  Can begin and end with a number or letter only
    #  Can contain hyphens, a-z, A-Z, 0-9
    #  1 - 63 chars allowed
    fqdn = re.compile(r'^[a-z0-9]([a-z-0-9-]{0,61}[a-z0-9])?$', re.IGNORECASE)

    #  Check if length of each DNS label < 63
    #  Match DNS label to pattern
    for label in hostname:
        if len(label) > 63:
            return False
        if not fqdn.match(label):
            return False

    #  Found no errors, returning True
    return True
    
#########################################################

def getTIDEIOCs(use_already_downloaded_IOC_files, ioctype, url,tide_apikey):
	filename = './tide_'+ ioctype + '.json'
	
	if not use_already_downloaded_IOC_files:
		method='GET'
		auth = base64.encodebytes(('%s:%s' % (tide_apikey,' ')).encode()).decode().replace('\n', '').strip()
		
		ssl._create_default_https_context = ssl._create_unverified_context
		
		opener = urllib.request.build_opener()
		opener.addheaders = opener.addheaders = [('Authorization', 'Basic %s' % auth ), ('Content-Type','application/x-www-form-urlencoded') ,('User-agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36')]
		urllib.request.install_opener(opener)
		urllib.request.urlretrieve(url, filename)
		
	file = open(filename, 'r')
	
	line_number=0
	for line in file:
		line_number +=1
		try:
			r_json=json.loads(line)
		except:
			raise Exception('Unable to load into a json format')
			
		#raise Exception(r_json)

		if r_json['type'] == 'HOST':
			updateDB(r_json['host'], r_json['property'], r_json['profile'])
		elif r_json['type'] == 'IP':
			updateDB(r_json['ip'], r_json['property'], r_json['profile'])
			
		if line_number % 100000 == 0:
			logging.debug('Loaded {} TIDE IOCs'.format(line_number))
	
	logging.info('Download ok, {} TIDE IOCs: {}'.format(ioctype,line_number))
	
#########################################################
def getPaloAltoAutoFocusIOCs(use_already_downloaded_IOC_files, paloalto_autofocus_apikey):
	data ={}
	filename = './paloalto_autofocus.csv'
	
	if not use_already_downloaded_IOC_files:
		method='GET'
		ssl._create_default_https_context = ssl._create_unverified_context
		
		opener = urllib.request.build_opener()
		opener.addheaders = opener.addheaders = [('apikey', paloalto_autofocus_apikey )]
		urllib.request.install_opener(opener)
		urllib.request.urlretrieve(paloalto_autofocus_url, filename)
	
	file=open(filename, 'r')
	
	content = file.readlines()

	line_number=0
	ioc_number=0
	for line in content:
		line_number +=1
		if is_fqdn(line) or ipaddress.ip_address(line):
			updateDB(line.strip(),'undefined','Palo Alto')
			ioc_number +=1
			
		if line_number % 10000 == 0:
			logging.debug('Loaded {} Palo Alto IOCs'.format(line_number))
		
	logging.info('Download ok, Palo Alto IOCs: {}'.format(ioc_number))
	file.close()
	
#########################################################	
def getFortiguardIOCs(use_already_downloaded_IOC_files, fortiguard_apikey):
	data ={}
	
	headers= {'Token': '{}'.format(fortiguard_apikey)}
	filename = './fortinet_all.stix'
	
	if not use_already_downloaded_IOC_files:
		response = requests.get(fortiguard_url, headers=headers, cookies=None, verify=True, timeout=(600,600), stream=True)
		
		url = response.json()[0]['data']
		response = requests.get(url, headers=headers, cookies=None, verify=True, timeout=(600,600), stream=True)
		
		open(filename, 'wb').write(gzip.decompress(response.content))

	file=open(filename, 'r')
	
	stix_package = STIXPackage.from_xml(filename)
	
	logging.info('Loading STIX package in memory OK')

	ttps = stix_package.ttps.to_dict().get('ttps')
	indicators = stix_package.indicators
		
	line_number=0
	for indicator in indicators:
		line_number +=1
		ttp_title = ''
		observable_dict = {}
		ttp_id=indicator.to_dict().get('indicated_ttps')[0].get('ttp').get('idref')
		for ttp_ref in ttps:
			if ttp_ref.get('id') == ttp_id:
				ttp_title= ttp_ref.get('title')

		for observable in indicator.observables:
			try:
				observable_dict = observable.to_dict()['object']['properties']
				IOC = {}
				if observable_dict.get('type')=='Domain Name':
					line = observable_dict.get('value')
				elif observable_dict.get('ip_address').get('address_value').get('condition') == 'Equals':
					line = observable_dict.get('ip_address').get('address_value').get('value')		

				if is_fqdn(line) or ipaddress.ip_address(line):
					updateDB(line,ttp_title,'Fortinet')
					IOC['item']=line
					IOC['description'] = ttp_title
					data[line] = IOC

			except:
				pass
		
		if line_number % 10000 == 0:
			logging.debug('Loaded {} Fortiguard IOCs'.format(line_number))
		

	logging.info('Download ok, Fortinet IOCs: {}'.format(len(data)))
	file.close()

#########################################################	

def getcyber_threat_coalition(use_already_downloaded_IOC_files):

	filename = './cyber_threat_coalition.csv'

	if not use_already_downloaded_IOC_files:
		#method='GET'
		ssl._create_default_https_context = ssl._create_unverified_context
		
		opener = urllib.request.build_opener()
		opener.addheaders = opener.addheaders = [('User-agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36')]
		urllib.request.install_opener(opener)
		urllib.request.urlretrieve(cyber_threat_coalition_url, filename)
	
	file=open(filename, 'r')
	
	content = file.readlines()

	line_number=0
	ioc_number=0
	for line in content:
		line_number +=1
		try:
			if is_fqdn(line) or ipaddress.ip_address(line):
				updateDB(line.strip(),'undefined','Cyber threat coalition')
				ioc_number +=1
		except:
			pass
			
		if line_number % 10000 == 0:
			logging.debug('Loaded {} Cyber threat coalition IOCs'.format(line_number))
		
	logging.info('Download ok, Cyber threat coalition IOCs: {}'.format(ioc_number))
	file.close()

#########################################################	

conn = initSQLlite()

getTIDEIOCs(use_already_downloaded_IOC_files, 'host', tide_hosts_url, tide_apikey)
getTIDEIOCs(use_already_downloaded_IOC_files, 'ip', tide_ips_url, tide_apikey)

getcyber_threat_coalition(use_already_downloaded_IOC_files)

if fortiguard_apikey:
	getFortiguardIOCs(use_already_downloaded_IOC_files, fortiguard_apikey)
	
if paloalto_autofocus_apikey:
	getPaloAltoAutoFocusIOCs(use_already_downloaded_IOC_files, paloalto_autofocus_apikey)

#cp = cProfile.Profile()
#cp.enable()
#cp.disable()
#cp.print_stats()
