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

logging.basicConfig(handlers = [logging.FileHandler('log/notable-timelines.log'), logging.StreamHandler()],level=logging.INFO,format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
age_IOCs_inactive_for_days = cfg['age_IOCs_inactive_for_days']
		
def get_iocs():

	conn = sqlite3.connect('IOCs.db')
	logging.info('Opened database successfully')

	query = conn.execute('''SELECT a.ioc, a.provider, a.first_seen
	FROM iocs a
	JOIN (select ioc, provider,
	COUNT(CASE WHEN provider = 'Palo Alto'  THEN 1 END) AS pan,
	COUNT(CASE WHEN provider = 'Fortinet' THEN 1 END) AS fortinet,
	COUNT(CASE WHEN provider = 'IID' THEN 1 END) AS iid,
	COUNT(CASE WHEN provider = 'FarsightSecurity'   THEN 1 END) AS nod,
	COUNT(*)
	from iocs group by ioc
	having count(*) > 4 and iid=1 and nod=1) b
	ON a.ioc = b.ioc
	ORDER BY a.ioc,a.first_seen''')

	cols = [column[0] for column in query.description]
	df= pd.DataFrame.from_records(data = query.fetchall(), columns = cols)

	for ioc in df.ioc.unique():
		#raise Exception(df.loc[df.ioc == ioc].provider.values[0])
		if df.loc[df.ioc == ioc].provider.values[0]=='FarsightSecurity' and df.loc[df.ioc == ioc].provider.values[1]=='IID':
			logging.info(df.loc[df.ioc == ioc])
			dates = df.loc[df.ioc == ioc].first_seen
			names = df.loc[df.ioc == ioc].provider + " " + df.loc[df.ioc == ioc].first_seen
			generate_report(dates,names,ioc)

def generate_report(dates,names,ioc):
	#Convert date strings (e.g. 2014-10-18) to datetime
	dates = [datetime.strptime(d, "%Y-%m-%dT%H:%M:%S") for d in dates]
	hour_interval = int(round((max(dates)-min(dates)).total_seconds()/3600/10,0))
		
	# Choose some nice levels
	levels = np.tile([-5, 5, -3, 3, -1, 1],
	int(np.ceil(len(dates)/6)))[:len(dates)]

	# Create figure and plot a stem plot with the date
	fig, ax = plt.subplots(figsize=(8.8, 4), constrained_layout=True)
	ax.set(title="Matplotlib release dates")

	ax.vlines(dates, 0, levels, color="tab:red")  # The vertical stems.
	ax.plot(dates, np.zeros_like(dates), "-o",
		color="k", markerfacecolor="w")  # Baseline and markers on it.

	# annotate lines
	for d, l, r in zip(dates, levels, names):
		ax.annotate(r, xy=(d, l),
			xytext=(-3, np.sign(l)*3), textcoords="offset points",
			horizontalalignment="right",
			verticalalignment="bottom" if l > 0 else "top")

	# format xaxis with 10 intervals
	ax.get_xaxis().set_major_locator(mdates.HourLocator(interval=hour_interval))
	ax.get_xaxis().set_major_formatter(mdates.DateFormatter("%Y-%m-%d %H:%M"))
	plt.setp(ax.get_xticklabels(), rotation=30, ha="right")

	# remove y axis and spines
	ax.get_yaxis().set_visible(False)
	for spine in ["left", "top", "right"]:
		ax.spines[spine].set_visible(False)

	ax.margins(y=0.1)
	plt.title('Detection timeline for ioc {}'.format(ioc))
	plt.savefig('timeline/{}_timeline.png'.format(ioc))
	plt.close(fig)
	logging.info('Generated timeline/{}_timeline.png successfully'.format(ioc))	
#########################################################			

get_iocs()