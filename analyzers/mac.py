from scapy.all import *
import sqlite3
import config
import os
from util import *

## remember this is from pov of scanner.py
##       vvvvvvvvv----- need this
macdb = "analyzers/data/nmap-prefix.db"
pconn = sqlite3.connect(macdb)

def getmanuf(mac):
	pc = pconn.cursor()
	pre = standardize_mac(mac)[:6]
	pc.execute("SELECT name FROM manuf WHERE prefix=?",(pre,))
	r = pc.fetchone()
	if r:
		return r[0]
	else:
		return ''


DB = config.DATABASE
conn = sqlite3.connect(DB)
c = conn.cursor()
try:
	c.execute("CREATE TABLE macaddrs (mac text, manuf text)")
except sqlite3.OperationalError:
	pass
conn.commit()
conn.close()

## two important definitions:
a_layers = [Ether]

def a_analyze(pkt):
	conn = sqlite3.connect(DB)
	c = conn.cursor()
	for mac in (pkt[Ether].src,pkt[Ether].dst):
		mac = standardize_mac(mac)
		c.execute("SELECT * FROM macaddrs WHERE mac=?",(mac,))
		if not c.fetchall():
			manuf = getmanuf(mac)
			c.execute("INSERT INTO macaddrs VALUES (?,?)",(mac,manuf))
	conn.commit()
	conn.close()
