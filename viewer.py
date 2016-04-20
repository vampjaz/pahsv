## this isn't a live updating viewer. i might write one eventually, but use this for now

from scapy.all import *
import sqlite3
import config
from analyzers import util

conn = sqlite3.connect(config.DATABASE)

def disp_host(mac):
	c = conn.cursor()
	mac = util.standardize_mac(mac)
	manuf = None
	c.execute("SELECT manuf FROM macaddrs WHERE mac=?",(mac,))
	r = c.fetchall()
	if r:
		manuf = r[0][0]
	ip = None
	c.execute("SELECT ip FROM ipaddrs WHERE mac=?",(mac,))
	r = c.fetchall()
	if r:
		ip = r[0][0]
	hn = None
	if ip:
		c.execute("SELECT hostname FROM hostnames WHERE ip=?",(ip,))
		r = c.fetchall()
		if r:
			hn = r[0][0]
	os = None
	c.execute("SELECT os FROM opsys WHERE mac=?",(mac,))
	r = c.fetchall()
	if r:
		os = r[0][0]
	if not hn:
		return
	print '-='*30 + '-'
	print "mac:",util.pprint_mac(mac)
	print "manuf:",manuf
	print "ip:",ip
	print "hostname:",hn
	print "os:",os


def disp_all():
	c = conn.cursor()
	c.execute("SELECT mac FROM macaddrs")
	for m in c.fetchall():
		disp_host(m[0])



disp_all()

conn.close()
