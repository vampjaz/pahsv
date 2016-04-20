def standardize_mac(mac):
	return ''.join(i for i in mac.upper() if i in "0123456789ABCDEF")

def pprint_mac(mac):
	mac = standardize_mac(mac)
	r = ''
	for i in range(6):
		r += mac[:2]
		r += ':'
		mac = mac[2:]
	return r.lower()[:-1]
