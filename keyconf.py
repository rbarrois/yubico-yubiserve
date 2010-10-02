#!/usr/bin/python
import sqlite, time
from sys import argv

con = sqlite.connect('yubikeys.sqlite')
cur = con.cursor()

if (len(argv)<3):
	print "YubiServe Key Management Tool 1.0\n"
	print " -a <publicname> <internalname> <aeskey>\tAdd a new key"
	print " -k <publicname>\t\t\t\tDelete a key from database"
	print " -d <publicname>\t\t\t\tDisable a key from database (it will be kept)"
	print " -e <publicname>\t\t\t\tEnable a key within the database\n"
else:
	if ((argv[1] == '-d') and (len(argv)>2)):
		cur.execute("SELECT * FROM yubikeys WHERE publicname = '" + argv[2] + "'")
		if (cur.rowcount == 0):
			print "Key not found."
		else:
			cur.execute("SELECT * FROM yubikeys WHERE publicname = '" + argv[2] + "' AND active = 'true'")
			if (cur.rowcount == 1):
				cur.execute("UPDATE yubikeys SET active = 'false' WHERE publicname = '" + argv[2] + "'")
				print "Key " + argv[2] + " disabled."
				con.commit()
			else:
				print "Key is already disabled."

	elif ((argv[1] == '-e') and (len(argv)>2)):
		cur.execute("SELECT * FROM yubikeys WHERE publicname = '" + argv[2] + "'")
		if (cur.rowcount == 0):
			print "Key not found."
		else:
			cur.execute("SELECT * FROM yubikeys WHERE publicname = '" + argv[2] + "' AND active = 'false'")
			if (cur.rowcount == 1):
				cur.execute("UPDATE yubikeys SET active = 'true' WHERE publicname = '" + argv[2] + "'")
				print "Key " + argv[2] + " enabled."
				con.commit()
			else:
				print "Key is already enabled."
	elif ((argv[1] == '-k') and (len(argv)>2)):
		cur.execute("SELECT * FROM yubikeys WHERE publicname = '" + argv[2] + "'")
		if (cur.rowcount == 0):
			print "Key not found."
		else:
			cur.execute("DELETE FROM yubikeys WHERE publicname = '" + argv[2] + "'")
			print "Key " + argv[2] + " deleted."
			con.commit()
	elif ((argv[1] == '-a') and (len(argv)>3)):
		if ((len(argv[2])<=16) and (len(argv[3]) <= 12) and (len(argv[4])<=32)):
			cur.execute("SELECT * FROM yubikeys WHERE publicname = '" + argv[2] + "'")
			if (cur.rowcount == 0):
				cur.execute("INSERT INTO yubikeys VALUES ('" + argv[2] + "', '" + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "', '" + argv[3] + "', '" + argv[4] + "', 'true', 1, 1)")
				con.commit()
				print "Key " + argv[2] + " added to database."
			else:
				print "Key is already into database. Delete it before adding the same key!"
	else:
		print "Not enough parameters. Try looking at " + argv[0] + " --help"
