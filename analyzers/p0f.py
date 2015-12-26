from scapy.all import *
import sqlite3
import config
import os
from util import *

load_module('p0f') ## for some reason you need p0f 2.x definitions for scapy's implementation

DB = config.DATABASE
conn = sqlite3.connect(DB)
c = conn.cursor()
try:
	c.execute("CREATE TABLE opsys (mac text, os text)")
except sqlite3.OperationalError:
	pass
conn.commit()
conn.close()

## two important definitions:
a_layers = [Ether,IP]

def a_analyze(pkt):
	mac = standardize_mac(pkt[Ether].src)
	try:
		os = p0f(pkt)
		os = ', '.join(i[0] + ':' + i[1] for i in os)
	except:
		return
	if os and (not 'UNKNOWN' in os):
		conn = sqlite3.connect(DB)
		c = conn.cursor()
		c.execute("SELECT * FROM opsys WHERE mac=?",(mac,))
		c.execute("INSERT INTO opsys VALUES (?,?)",(mac,os))
		conn.commit()
		conn.close()
