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

logging.basicConfig(handlers = [logging.FileHandler('log/dedup-iocs-to-db.log'), logging.StreamHandler()],level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
		
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
	
def generate_logics(n_sets):
    """Generate intersection identifiers in binary (0010 etc)"""
    for i in range(1, 2**n_sets):
        yield bin(i)[2:].zfill(n_sets)
		
#########################################################

def generate_petal_labels(datasets):
    datasets = list(datasets)
    n_sets = len(datasets)
    dataset_union = set.union(*datasets)
    universe_size = len(dataset_union)
    petal_labels = {}
    petal_sets = {}
    for logic in generate_logics(n_sets):
        included_sets = [
            datasets[i] for i in range(n_sets) if logic[i] == "1"
        ]
        excluded_sets = [
            datasets[i] for i in range(n_sets) if logic[i] == "0"
        ]
        petal_set = (
            (dataset_union & set.intersection(*included_sets)) -
            set.union(set(), *excluded_sets)
        )
        petal_labels[logic] = logic
        petal_sets[logic]=petal_set

    return petal_sets

#########################################################

def dedupIOCtoDB(providers,conn):

	ioc_sets = {}
	deduplicated_sets = {}
	
	for provider in providers:
		ioc_sets[provider] = getIOCs(conn,'provider = "{}"'.format(provider))

	deduplicated_sets = generate_petal_labels(ioc_sets.values())
	deduplicated_sets_keys = list(deduplicated_sets.keys())
	
	ioc_sets_keys = list(ioc_sets.keys())
	
	#exclude AISCOMM, EmergingThreats, FarsightSecurity,  IID, SURBL
	for provider in ioc_sets_keys:
		if provider == 'AISCOMM' or provider == 'EmergingThreats' or provider == 'FarsightSecurity' or provider == 'IID' or provider == 'SURBL':
			for binary_id in deduplicated_sets_keys:
				if binary_id[ioc_sets_keys.index(provider)] == '1' and binary_id in deduplicated_sets.keys():
					deduplicated_sets.pop(binary_id)
	
	for binary_id in deduplicated_sets:
		provider = []
		for binary_bin in range(0,len(binary_id)):
			if binary_id[binary_bin] == '1':
				provider.append(ioc_sets_keys[binary_bin])
		first_provider = provider[0]
		provider_display = ' and '.join(provider)
		
		cur = conn.cursor()
		for ioc in deduplicated_sets[binary_id]:
			cur.execute('insert into deduplicated_iocs (ioc,provider,description) select "'+ioc+'","'+provider_display+'",description from iocs where id="'+ioc+first_provider+'"')
		conn.commit()

	logging.info('IOC deduplication successful')
		
########################################

conn = initSQLlite()
providers = getProviders(conn)
dedupIOCtoDB(providers,conn)
