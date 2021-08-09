import requests
import json
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

logging.basicConfig(handlers = [logging.FileHandler('log/push-to-csp.log'), logging.StreamHandler()],level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
csp_apikey = cfg['csp_apikey']
		
#########################################################
	
def initSQLlite():
	conn = sqlite3.connect('IOCs.db')
	logging.info('Opened database successfully')
	return conn
		
#########################################################

def getProviders(conn):
	cur = conn.cursor()
	cur.execute('select distinct provider from deduplicated_iocs')
	providers = numpy.unique(cur.fetchall())
	conn.commit()
	return providers

#########################################################

def getIOCs(conn,filter):
	cur = conn.cursor()
	cur.execute('select ioc,description from deduplicated_iocs where {}'.format(filter))
	iocs = cur.fetchall()
	return iocs

#########################################################

def get_named_lists(named_list_prefix,headers):
	list_of_named_lists=[]
	response = requests.get('https://csp.infoblox.com/api/atcfw/v1/named_lists', headers=headers, verify=True, timeout=(300,300))
	r_json = response.json()['results']
	for named_list in r_json:
		if re.match('^' + named_list_prefix + ' \d+', named_list['name']) or re.match('^' + named_list_prefix + '$', named_list['name']):
			list_of_named_lists.append(named_list)
			
	return list_of_named_lists

#########################################################	

def update_to_csp(new_IOCs, csp_apikey, provider):

	headers= {'Authorization': 'Token {}'.format(csp_apikey)}

	#Get all named_lists ################################
	list_of_named_lists = get_named_lists(provider,headers)

	# Getting the domain names that are to be added.
	new_domains = list(new_IOCs.keys())

	#Create the List ####################################
	name_list_names = False
	for named_list in list_of_named_lists:
		if named_list['name'] == provider:
			name_list_names = True

	if not name_list_names:
		json_to_create = '{"name": "'+ provider+'", "type": "custom_list", "confidence_level": "MEDIUM", "threat_level": "MEDIUM", "items_described": [ { "description": "do not remove", "item": "must_have_at_least_1_bad_domain.xyz" }]}'
		logging.info("Adding Named_list {}".format(provider))
		res = requests.post('https://csp.infoblox.com/api/atcfw/v1/named_lists', headers=headers, data=json_to_create, verify=True, timeout=(300,300))

	#Update available Named Lists #######################	
	list_of_named_lists = get_named_lists(provider,headers)
	named_list=list_of_named_lists[0]
	for named_list_in_list in list_of_named_lists:
		if named_list_in_list['name'] == provider:
			named_list=named_list_in_list

	# Extract items in list and perform pagination
	count = named_list['item_count']
	batch_of_read = 50000
	batches = int(count/batch_of_read)+1
	existing_domains = []
	# Getting domains in batches of {batch_of_read} domains to reduce load
	for i in range(0, batches):
		logging.info(f"Getting batch {i} of {batch_of_read} domains.")
		response = requests.get(
			'https://csp.infoblox.com/api/atcfw/v1/named_lists/{}'.format(
				named_list['id']), headers=headers, verify=True,
			params={'_limit': batch_of_read, '_offset': i*batch_of_read},
			timeout=(300, 300))
		print(response)
		existing_domains.extend(response.json()['results']['items'])

	# Add to list ########################################
	logging.debug('{:<20}  {:<50}'.format('-- Description --','-- IOC --'))

	# Filtering IOCs to be added
	domains_to_add = set(new_domains) - set(existing_domains)
	IOCs_to_add = []
	for domain in domains_to_add:
		IOCs_to_add.append(new_IOCs[domain])
	json_to_add = {}

	batch_of_write = 10000
	# print(f'Items to be added: {IOCs_to_add}')
	print(f'Number of Items to be added: {len(IOCs_to_add)}')
	# We are adding sets of {batch_of_write} domains
	if IOCs_to_add:
		all_batches = create_batches(batch_of_write, IOCs_to_add)
		for idx,batch in enumerate(all_batches):
			print(f'Batch number: {idx}')
			json_to_add['inserted_items_described'] = batch
			logging.info("Adding {} entries in named_list {}, {}".format(
				len(json_to_add['inserted_items_described']), named_list['name'],
				named_list['id']))
			response = requests.patch(
				'https://csp.infoblox.com/api/atcfw/v1/named_lists/{}/items'.format(
					named_list['id']), headers=headers,
				data=json.dumps(json_to_add, indent=4, sort_keys=True), verify=True,
				timeout=(300, 300))
			print(response)
			time.sleep(5)
			# ToDo: update with a retry logic if the request fails.
	else:
		logging.info("New IOCs are same as existing ones.")

#########################################################

def create_batches(batch_of, total):
	start = 0
	num = int(len(total) / batch_of) + 1
	whole_list = []
	while num:
		end = start + batch_of
		whole_list.append(total[start:end])
		start += batch_of
		num -= 1
	return whole_list



def formatandimportIOCs(providers):
	for provider in providers:
		new_IOCs={}
		dbfetch = getIOCs(conn, 'provider="{}"'.format(provider))
		for entry in dbfetch:
			new_IOCs[entry[0]]					= {}
			# {'name_1': {'item': 'name_1','description': 'whatever'}, 'name_2':{}}
			new_IOCs[entry[0]]['item']			= entry[0]
			new_IOCs[entry[0]]['description']	= entry[1]
		update_to_csp(new_IOCs, csp_apikey, provider)

#########################################################		

conn = initSQLlite()
providers = getProviders(conn)
formatandimportIOCs(providers)

