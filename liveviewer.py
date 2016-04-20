#from scapy.all import *
import sqlite3, time, sys
import config
from analyzers import util
from termsize import get_terminal_size

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
	return (mac,manuf,ip,hn,os)


def rate(dev): ## "rating" to tell how interesting a device is
	## want to automize this soon (import a weight from the module)
	r = 0
	if dev[0]:
		r += 2
	if dev[1]:
		r += 1
	if dev[2]:
		r += 3
	if dev[3]:
		r += 7
	if dev[4]:
		r += 2
	if dev[2] == '0.0.0.0' or dev[2] == '255.255.255.255': #bogus ipaddrs
		r -= 6
	if dev[0] == 'FFFFFFFFFFFF' or dev[0] == '000000000000':
		r -= 3
	return r

def pad(a,x):
	if x == 0 and a is None:
		return ''
	elif a is None:
		a = '[none]'
	return (x-len(a))*' ' + a

def disp_all():
	c = conn.cursor()
	c.execute("SELECT mac FROM macaddrs")
	hosts = []
	for m in c.fetchall():
		hosts.append(disp_host(m[0]))
	hostrate = []
	for h in hosts:
		hostrate.append((rate(h),h))
	hostrate.sort(key=lambda l:l[0])
	hostrate = list(reversed(hostrate))
	sys.stderr.write("\x1b[2J\x1b[H")
	termw, termh =  get_terminal_size()
	for h in hostrate[:termh-2]:
		d = h[1]
		if d[0] and d[2]: # only print if it had an IP and MAC
			print (pad(d[3],20) + ': ' + pad(d[2],20) + ', ' + pad(util.pprint_mac(pad(d[0],0)),19) + '   (' + pad(d[1],0) + ')   ' + pad(d[4],0))[:termw]
	print "Total entries: {}".format(len(hostrate))

while 1:
	disp_all()
	time.sleep(2)

conn.close()
