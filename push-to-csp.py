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

logging.basicConfig(handlers = [logging.FileHandler('log/push-to-csp.log'), logging.StreamHandler()],level=logging.DEBUG,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
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
		if re.match('^'+named_list_prefix+'\d+', named_list['name']):
			list_of_named_lists.append(named_list)
			
	return list_of_named_lists

#########################################################	

def update_to_csp(new_IOCs, csp_apikey, provider):
		
	headers= {'Authorization': 'Token {}'.format(csp_apikey)}
	max_records_per_csp_list=10000
	named_list_prefix='{} '.format(provider)
	existing_IOCs= {}
	IOCs_to_add = [{'description': 'do not remove', 'item': 'must_have_at_least_1_bad_domain.xyz'}]
	IOCs_to_remove = []

	#Get all named_lists ################################
	list_of_named_lists = get_named_lists(named_list_prefix,headers)
	
	#Get named lists content ############################
	for name_list in list_of_named_lists:
		response = requests.get('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}'.format(name_list['id']), headers=headers, verify=True, timeout=(300,300))
		for item in response.json()['results']['items_described']:
			item['named_list_id'] = name_list['id']
			existing_IOCs[item['item']] = item


	#Deduplicate to get the IOCs to add #################
	test= set(new_IOCs)
	test2 = set(existing_IOCs)
	diff = set(new_IOCs).difference(set(existing_IOCs))
	IOCs_to_add  = [new_IOCs[k] for k in diff]
	
			
	#Get the IOCs to remove #############################
	diff = set(existing_IOCs).difference(set(new_IOCs))	
	IOCs_to_remove  = [existing_IOCs[k] for k in diff]

	#Clean the lists#####################################
	for name_list in list_of_named_lists:
		filtered_IOCs_to_remove=[]
		for IOC_to_remove in IOCs_to_remove:
			if 'named_list_id' in IOC_to_remove and IOC_to_remove['named_list_id'] == name_list['id']:
				del IOC_to_remove['named_list_id']
				filtered_IOCs_to_remove.append(IOC_to_remove)
		if len(filtered_IOCs_to_remove) > 0:
			json_to_delete={}
			json_to_delete['items_described']=filtered_IOCs_to_remove
			logging.info("Cleaning {} entries in named_list {}, {}".format(len(filtered_IOCs_to_remove),name_list['name'],name_list['id']))
			response = requests.delete('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}/items'.format(name_list['id']), headers=headers, data=json.dumps(json_to_delete, indent=4, sort_keys=True), verify=True, timeout=(300,300))
			
	
	#Determining if additional lists are required #######
	named_lists_current_capacity = max_records_per_csp_list * len(list_of_named_lists)
	named_list_capacity_required = len(existing_IOCs) - len(IOCs_to_remove) + len (IOCs_to_add)
	number_of_named_list_to_create = max(0,math.ceil((named_list_capacity_required - named_lists_current_capacity) / max_records_per_csp_list))
		
	logging.info('named_lists_current_capacity = {}, named_list_capacity_required = {}, number_of_named_list_to_create = {}'.format(named_lists_current_capacity,named_list_capacity_required,number_of_named_list_to_create))

	
	#Create the List ####################################
	name_list_names=[0]
	for named_list in list_of_named_lists:
		name_list_names.append(int(re.search('\d+$', named_list['name']).group(0)))
	
	for i in range ( 1 , number_of_named_list_to_create+1):
		json_to_create = '{"name": "'+ named_list_prefix + str(i+max(name_list_names)) +'", "type": "custom_list", "confidence_level": "MEDIUM", "threat_level": "MEDIUM", "items_described": [ { "description": "do not remove", "item": "must_have_at_least_1_bad_domain.xyz" }]}'
		logging.info("Adding Named_list {}".format(named_list_prefix + str(i+max(name_list_names))))
		response = requests.post('https://csp.infoblox.com/api/atcfw/v1/named_lists', headers=headers, data=json_to_create, verify=True, timeout=(300,300))


	#Update available Named Lists #######################	
	list_of_named_lists = get_named_lists(named_list_prefix,headers)
	
	
	#Add to list ########################################
	logging.debug('{:<20}  {:<50}'.format('-- Description --','-- IOC --'))
	i=0
	for named_list in list_of_named_lists:
		IOCs_to_add_to_list = []
		j=0
		while int(j + int(named_list['item_count'])) < max_records_per_csp_list and i < len(IOCs_to_add):
			IOCs_to_add_to_list.append(IOCs_to_add[i])
			logging.debug('{:<20}  {:<50}'.format(IOCs_to_add[i].get('description',''),IOCs_to_add[i].get('item','')))
			i +=1
			j +=1
		json_to_add={}
		json_to_add['items_described'] = IOCs_to_add_to_list
		
		logging.info("Adding {} entries in named_list {}, {}".format(len(IOCs_to_add_to_list),named_list['name'],named_list['id']))
		response = requests.post('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}/items'.format(named_list['id']), headers=headers, data=json.dumps(json_to_add, indent=4, sort_keys=True), verify=True, timeout=(300,300))
		try:
			response.raise_for_status()
		except requests.exceptions.HTTPError as e:
			return "Error: " + str(e)

#########################################################		

def formatandimportIOCs(providers):
	for provider in providers:
		new_IOCs={}
		dbfetch = getIOCs(conn, 'provider="{}"'.format(provider))
		for entry in dbfetch:
			new_IOCs[entry[0]]					= {}
			new_IOCs[entry[0]]['item']			= entry[0]
			new_IOCs[entry[0]]['description']	= entry[1]
		update_to_csp(new_IOCs, csp_apikey, provider)

#########################################################		

conn = initSQLlite()
providers = getProviders(conn)
formatandimportIOCs(providers)