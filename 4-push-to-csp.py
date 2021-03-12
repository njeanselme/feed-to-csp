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

	#Deduplicate to get the IOCs to add #################
	IOCs_to_add  = [new_IOCs[k] for k in set(new_IOCs)]
	
	#Create the List ####################################
	name_list_names= False
	for named_list in list_of_named_lists:
		if named_list['name'] == provider:
			name_list_names = True

	if not name_list_names:
		json_to_create = '{"name": "'+ provider+'", "type": "custom_list", "confidence_level": "MEDIUM", "threat_level": "MEDIUM", "items_described": [ { "description": "do not remove", "item": "must_have_at_least_1_bad_domain.xyz" }]}'
		logging.info("Adding Named_list {}".format(provider))
		response = requests.post('https://csp.infoblox.com/api/atcfw/v1/named_lists', headers=headers, data=json_to_create, verify=True, timeout=(300,300))

	#Update available Named Lists #######################	
	list_of_named_lists = get_named_lists(provider,headers)
	named_list=list_of_named_lists[0]
	for named_list_in_list in list_of_named_lists:
		if named_list_in_list['name'] == provider:
			named_list=named_list_in_list

	#Add to list ########################################
	logging.debug('{:<20}  {:<50}'.format('-- Description --','-- IOC --'))

	json_to_add={}
	json_to_add['items_described'] = IOCs_to_add

	#Getting list
	response = requests.get('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}'.format(named_list['id']), headers=headers, verify=True, timeout=(300,300))
	list_json= response.json()['results']

	#Modifying list
	list_json.pop('items')
	list_json['items_described'] = json_to_add['items_described']

	#Put call
	logging.info("Adding {} entries in named_list {}, {}".format(len(json_to_add['items_described']),named_list['name'],named_list['id']))
	response = requests.put('https://csp.infoblox.com/api/atcfw/v1/named_lists/{}'.format(named_list['id']), headers=headers, data=json.dumps(list_json, indent=4, sort_keys=True), verify=True, timeout=(300,300))
	print(response)
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
