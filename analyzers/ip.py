from scapy.all import *
import sqlite3
import config
import os
from util import *

DB = config.DATABASE
conn = sqlite3.connect(DB)
c = conn.cursor()
try:
	c.execute("CREATE TABLE ipaddrs (mac text, ip text)")
except sqlite3.OperationalError:
	pass
conn.commit()
conn.close()

## two important definitions:
a_layers = [Ether,IP]

def a_analyze(pkt):
	conn = sqlite3.connect(DB)
	c = conn.cursor()
	for mac,ip in zip((pkt[Ether].src,pkt[Ether].dst),(pkt[IP].src,pkt[IP].dst)):
		mac = standardize_mac(mac)
		c.execute("SELECT * FROM ipaddrs WHERE mac=?",(mac,))
		if not c.fetchall():
			c.execute("INSERT INTO ipaddrs VALUES (?,?)",(mac,ip))
	conn.commit()
	conn.close()
