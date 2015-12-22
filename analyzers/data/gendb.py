import sqlite3,os

fn = "nmap-mac-prefixes"
db = "nmap-prefix.db"

if os.path.exists(db):
	os.remove(db)

conn = sqlite3.connect(db)
c = conn.cursor()

c.execute("CREATE TABLE manuf (prefix text, name text)")

fd = open(fn)

for i in fd.readlines():
	pre,name = i.split(' ',1)
	if not pre == '#':
		c.execute("INSERT INTO manuf VALUES (?,?)",(pre.strip(),name.strip()))

conn.commit()
conn.close()
