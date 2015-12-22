from scapy.all import *
import sqlite3
import sys,os
import config

analyzers = []

for i in config.ANALYZE:
	try:
		exec "from analyzers.{} import a_layers,a_analyze".format(i)
		analyzers.append((a_layers,a_analyze))
	except KeyboardInterrupt:
		print "error loading analyzer:",i


def process(pkt):
	for layers,func in analyzers:
		run = True
		for i in layers:
			if not pkt.haslayer(i):
				run = False
		if run:
			func(pkt)


def main(name):
	if os.path.exists(name):
		print repr(rdpcap(name, prn=process))
	else:
		print repr(sniff(iface=name, prn=process))

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "usage: python scanner.py <pcap file OR lan interface>"
		sys.exit(1)
	main(sys.argv[1])
