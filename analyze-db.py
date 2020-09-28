import json
import re
import math
import logging
import time
import sqlite3
import numpy
from venn import venn
import matplotlib
from matplotlib import pyplot as plt
import yaml

with open("config.yml", "r") as ymlfile:
    cfg = yaml.safe_load(ymlfile)

#########################################################	

logging.basicConfig(handlers = [logging.FileHandler('log/analyze-db.log'), logging.StreamHandler()],level=logging.DEBUG,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
#logging.basicConfig(handlers = [logging.FileHandler('log/feed-to-infoblox-csp.log'), logging.StreamHandler()], level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
age_IOCs_inactive_for_days = cfg['age_IOCs_inactive_for_days']
		
#########################################################
	
def initSQLlite():
	conn = sqlite3.connect('IOCs.db')
	logging.info('Opened database successfully')
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
		
def generate_report(providers,conn):
	ioc_sets = {}
	display_sets = {}
	for provider in providers:
		ioc_sets[provider] = getIOCs(conn,'provider = "{}"'.format(provider))
	
	if 'Fortinet' in providers:
		display_sets['Fortinet'] = ioc_sets['Fortinet']
	if 'Palo Alto' in providers:
		display_sets['Palo Alto']= ioc_sets['Palo Alto']
	if 'FarsightSecurity' in providers:
		display_sets['FarsightSecurity']=ioc_sets['FarsightSecurity']
	
	display_sets['Infoblox'] = set()
	for provider in set(ioc_sets).difference(set(display_sets)):
		display_sets['Infoblox'].update(ioc_sets[provider])
	
	plt.figure(figsize=(4,4))
	v= venn(display_sets)
	plt.title('Vendor IOCs overlap on active threats during last {}days'.format(age_IOCs_inactive_for_days))
	plt.savefig('IOCs_overlap.png')

#########################################################			

conn = initSQLlite()
providers = getProviders(conn)
generate_report(providers,conn)
