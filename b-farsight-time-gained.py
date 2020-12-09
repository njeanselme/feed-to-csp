import json
import re
import math
import logging
import time
import sqlite3
import numpy as np
import pandas as pd
import seaborn as sns
from venn import venn
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import yaml
import whois
from datetime import datetime

with open("config.yml", "r") as ymlfile:
    cfg = yaml.safe_load(ymlfile)

#########################################################	

logging.basicConfig(handlers = [logging.FileHandler('log/farsight-time-gained.log'), logging.StreamHandler()],level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

#########################################################	
#['AISCOMM' 'CrowdStrike' 'Cyber threat coalition' 'EmergingThreats' 'FarsightSecurity' 'Fortinet' 'IID' 'Palo Alto' 'SURBL']
		
def generate_report():

	conn = sqlite3.connect('IOCs.db')
	logging.info('Opened database successfully')

	query = conn.execute('''SELECT ioc, provider, first_seen, description FROM iocs ORDER BY ioc''')
	
	cols = [column[0] for column in query.description]
	df= pd.DataFrame.from_records(data = query.fetchall(), columns = cols)
	
	# set farsight first seen as baseline - farsight_first_seen
	df2= df.loc[df['provider'] == 'FarsightSecurity', ('ioc', 'first_seen')]
	df2.rename(columns = {'first_seen':'farsight_first_seen'}, inplace = True)
	df3 = pd.merge(df,df2,on='ioc',how='inner')

	df3.drop(df3[df3.description == 'Policy_NewlyObservedDomains'].index, inplace=True) #to remove from graph
	#df3.drop(df3[df3.provider == 'FarsightSecurity'].index, inplace=True) #to remove from graph
	#df3.drop(df3[df3.provider == 'CrowdStrike'].index, inplace=True) #to remove from graph
	df3.drop(df3[df3.provider == 'Cyber threat coalition'].index, inplace=True) #to remove from graph
	#df3.drop(df3[df3.provider == 'SURBL'].index, inplace=True) #to remove from graph
	df3.drop(df3[df3.provider == 'EmergingThreats'].index, inplace=True) #to remove from graph
	#df3.drop(df3[df3.provider == 'Palo Alto'].index, inplace=True) #to remove from graph
	#df3.drop(df3[df3.provider == 'IID'].index, inplace=True) #to remove from graph
	#df3.drop(df3[df3.provider == 'Fortinet'].index, inplace=True) #to remove from graph
	
	df3['time_delta_human'] = pd.to_datetime(df3['first_seen']) - pd.to_datetime(df3['farsight_first_seen'])
	df3['time_delta'] 	= (pd.to_datetime(df3['first_seen']) - pd.to_datetime(df3['farsight_first_seen'])).dt.total_seconds()/3600	
	average_time_gain 	= round(df3['time_delta'].mean(),1)
	
	#clean graph
	df3.drop(df3[df3.time_delta < -5].index, inplace=True)
	df3.drop(df3[df3.time_delta > 300].index, inplace=True)	
	
	# Create the data
	x = df3.time_delta
	g = df3.provider
	df = pd.DataFrame(dict(x = x, g = g))

	# Initialize the FacetGrid object
	pal = sns.cubehelix_palette(10, rot=-.25, light=.7)
	g = sns.FacetGrid(df, row="g", hue="g", aspect=15, height=1, palette=pal)
	
	g.map(sns.kdeplot, "x", bw_adjust=.15, clip_on=False, fill=True, common_norm=True, alpha=1, linewidth=1.5)

	# Define and use a simple function to label the plot in axes coordinates
	def label(x, color, label):
		label = label + '\n{}h\n{} IOCs'.format(
			round(df3[df3.provider == label].time_delta.mean(),1),
			len(df3[df3.provider == label].index))
		ax = plt.gca()
		ax.text(0, .2, label, fontweight="bold", color=color, ha="left", va="center", transform=ax.transAxes)
	
	g.map(label, "x")
	#plt.xlim(-50, None)
	#plt.ylabel("IOCs")
	plt.xlabel("Delay to Farsight NOD in hours")

	# Set the subplots to overlap
	g.fig.subplots_adjust(hspace=0.5)

	# Remove axes details that don't play well with overlap
	g.set_titles('')
	g.set(yticks=[])
	g.despine(bottom=True, left=True)

	plt.title('Average time gain: {}hours'.format(average_time_gain))
	plt.savefig('images/Farsight_timeline.png')
	logging.info('Generated images/Farsight_timeline.png successfully')
#########################################################			

generate_report()
