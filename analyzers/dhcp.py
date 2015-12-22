from scapy.all import *
import sqlite3
import config

def getopt(pkt,opt):
	a = None
	for i in pkt.fields['options']:
		 if i[0] == opt and len(i)>1:
			 return i[1]
	if a:
		return a[0]

DB = config.DATABASE
conn = sqlite3.connect(DB)
c = conn.cursor()
try:
	c.execute("CREATE TABLE hostnames (ip text, hostname text)")
except sqlite3.OperationalError:
	pass
conn.commit()
conn.close()

a_layers = [Ether,DHCP]

def a_analyze(pkt):
	conn = sqlite3.connect(DB)
	c = conn.cursor()
	hn = getopt(pkt[DHCP],'hostname')
	ip = getopt(pkt[DHCP],'requested_addr')
	c.execute("SELECT * FROM hostnames WHERE hostname=?",(hn,))
	if not c.fetchall():
		c.execute("INSERT INTO hostnames VALUES (?,?)",(ip,hn))
	conn.commit()
	conn.close()
