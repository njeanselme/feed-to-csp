import re
import math
import logging
import time
import sqlite3
import numpy
import yaml

with open("config.yml", "r") as ymlfile:
    cfg = yaml.safe_load(ymlfile)

#########################################################	

logging.basicConfig(handlers = [logging.FileHandler('log/dedup-iocs-to-db.log'), logging.StreamHandler()],level=logging.DEBUG,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#logging.basicConfig(handlers = [logging.FileHandler('log/dedup-iocs-to-db.log'), logging.StreamHandler()], level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		
#########################################################
	
def initSQLlite():
	conn = sqlite3.connect('IOCs.db')
	logging.info('Opened database successfully')
	conn.execute('''create table if not exists deduplicated_iocs
         (ioc               text not null primary key,
         provider          text               not null,
         description       text);''')
         
	logging.info('Table created successfully')
	
	conn.execute('''delete from deduplicated_iocs''')
	conn.commit()
	
	logging.info('Table cleaned successfully')

	return conn
		
#########################################################

def getProviders(conn):
	cur = conn.cursor()
	cur.execute('select distinct provider from iocs')
	providers = numpy.unique(cur.fetchall())
	conn.commit()
	return providers

#########################################################

def getIOCs(conn,filter):
	cur = conn.cursor()
	cur.execute('select ioc from iocs where {}'.format(filter))
	iocs = set(numpy.unique(cur.fetchall()))
	return iocs
		
#########################################################
		
def dedupIOCtoDB(providers,conn):
	ioc_sets = {}
	temporary_sets = {}
	deduplicated_sets = {}
	
	for provider in providers:
		ioc_sets[provider] = getIOCs(conn,'provider = "{}"'.format(provider))
	
	if 'Fortinet' in providers:
		temporary_sets['Fortinet'] = ioc_sets['Fortinet']
	if 'Palo Alto' in providers:
		temporary_sets['Palo Alto']= ioc_sets['Palo Alto']
	if 'Cyber threat coalition' in providers:
		temporary_sets['Cyber threat coalition'] = ioc_sets['Cyber threat coalition']


	temporary_sets['Infoblox'] = set()
	for provider in set(ioc_sets).difference(set(temporary_sets)):
		temporary_sets['Infoblox'].update(ioc_sets[provider])
	
	#petal_set = ((dataset_union & set.intersection(*included_sets)) - set.union(set(), *excluded_sets)
	
	if 'Fortinet' in providers and 'Palo Alto' in providers:
		deduplicated_sets['Fortinet'] = ioc_sets['Fortinet'].difference(temporary_sets['Infoblox'].union(ioc_sets['Palo Alto']))
		deduplicated_sets['Palo Alto'] = ioc_sets['Palo Alto'].difference(temporary_sets['Infoblox'].union(ioc_sets['Fortinet']))
		deduplicated_sets['Palo Alto and Fortinet'] = ioc_sets['Fortinet'].intersection(ioc_sets['Palo Alto'])
	elif 'Fortinet' in providers:
		deduplicated_sets['Fortinet'] = ioc_sets['Fortinet'].difference(temporary_sets['Infoblox'])
	elif 'Palo Alto' in providers:
		deduplicated_sets['Palo Alto'] = ioc_sets['Palo Alto'].difference(temporary_sets['Infoblox'])

	if 'Cyber threat coalition' in providers and 'Fortinet' in providers and 'Palo Alto' in providers:
		deduplicated_sets['Cyber threat coalition'] = ioc_sets['Cyber threat coalition'].difference(temporary_sets['Infoblox'].union(ioc_sets['Palo Alto']).union(ioc_sets['Fortinet']))

	for provider in deduplicated_sets:
		if provider == 'Palo Alto and Fortinet':
			providersearch = 'Fortinet'
		else:
			providersearch = provider
		for ioc in deduplicated_sets[provider]:
			cur = conn.cursor()
			cur.execute('insert into deduplicated_iocs (ioc,provider,description) select "'+ioc+'","'+provider+'",description from iocs where id="'+ioc+providersearch+'"')
			conn.commit()

	logging.info('IOC deduplication successful')
		
########################################

conn = initSQLlite()
providers = getProviders(conn)
dedupIOCtoDB(providers,conn)
