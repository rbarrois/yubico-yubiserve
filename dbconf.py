#!/usr/bin/python
import sqlite, time, random, re
from sys import argv

def randomChars(max):
	retVal = ''
	for i in range(0, max):
		rand = random.randrange(0, 63)
		if (rand>36):
			retVal += chr(rand-36+96)	# Starting with 'a'
		elif (rand>10):
			retVal += chr(rand-10+64)	# Starting with 'A'
		else:							# Starting with '0'
			retVal += chr(rand+47)
	return retVal

con = sqlite.connect('yubikeys.sqlite')
cur = con.cursor()

if (len(argv)<2):
	print ' == YubiServe Key Management Tool 2.0 ==\n'
	print ' -ya <nickname> <publicid> <secretid> <aeskey>\tAdd a new Yubikey'
	print ' -yk <nickname>\t\t\t\t\tDelete a Yubikey'
	print ' -yd <nickname>\t\t\t\t\tDisable a Yubikey'
	print ' -ye <nickname>\t\t\t\t\tEnable a Yubikey'
	print ' -yl\t\t\t\t\t\tList all yubikeys in database\n'

	print ' -ha <nickname> <publicid> <key>\t\tAdd a new OATH token'
	print ' -hk <nickname>\t\t\t\t\tDelete a OATH token'
	print ' -hd <nickname>\t\t\t\t\tDisable a OATH token'
	print ' -he <nickname>\t\t\t\t\tEnable a OATH token'
	print ' -hl\t\t\t\t\t\tList all OATH tokens in database\n'

	print ' -aa <nickname>\t\t\t\t\tGenerate an API Key'
	print ' -ak <nickname>\t\t\t\t\tRemove an API Key'
	print ' -al\t\t\t\t\t\tList all API Keys in database\n'

else:
	if argv[1][0:2] == '-y': # Yubico Yubikey
		if (argv[1][2] == 'd') and (len(argv)>2):
			nickname = re.escape(argv[2])
			cur.execute("SELECT * FROM yubikeys WHERE nickname = '" + nickname + "'")
			if (cur.rowcount == 0):
				print 'Key not found.'
			else:
				cur.execute("SELECT * FROM yubikeys WHERE nickname = '" + nickname + "' AND active = 'true'")
				if (cur.rowcount == 1):
					cur.execute("UPDATE yubikeys SET active = 'false' WHERE nickname = '" + nickname + "'")
					print "Key '" + nickname + "' disabled."
					con.commit()
				else:
					print 'Key is already disabled.'

		elif (argv[1][2] == 'e') and (len(argv)>2):
			nickname = re.escape(argv[2])
			cur.execute("SELECT * FROM yubikeys WHERE nickname = '" + nickname + "'")
			if (cur.rowcount == 0):
				print 'Key not found.'
			else:
				cur.execute("SELECT * FROM yubikeys WHERE nickname = '" + nickname + "' AND active = 'false'")
				if (cur.rowcount == 1):
					cur.execute("UPDATE yubikeys SET active = 'true' WHERE nickname = '" + nickname + "'")
					print "Key '" + nickname + "' enabled."
					con.commit()
				else:
					print 'Key is already enabled.'
		elif (argv[1][2] == 'k') and (len(argv)>2):
			nickname = re.escape(argv[2])
			cur.execute("SELECT * FROM yubikeys WHERE nickname = '" + nickname + "'")
			if (cur.rowcount == 0):
				print 'Key not found.'
			else:
				cur.execute("DELETE FROM yubikeys WHERE nickname = '" + nickname + "'")
				print "Key '" + nickname + "' deleted."
				con.commit()
		elif (argv[1][2] == 'a') and (len(argv)>4):
			nickname = re.escape(argv[2])
			if ((len(argv[2])<=16) and (len(argv[3]) <= 16) and (len(argv[4]) <= 12) and (len(argv[5])<=32)):
				cur.execute("SELECT * FROM yubikeys WHERE nickname = '" + argv[2] + "' OR publicname = '" + argv[3] + "'")
				if (cur.rowcount == 0):
					cur.execute("INSERT INTO yubikeys VALUES ('" + argv[2] + "', '" + argv[3] + "', '" + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "', '" + argv[4] + "', '" + argv[5] + "', 'true', 1, 1)")
					con.commit()
					print "Key '" + argv[2] + "' added to database."
				else:
					print 'Key is already into database. Delete it before adding the same key!'
			else:
				print 'Nickname and publicid must be max 16 characters long.'
				print 'Secretid must be 12 characters max, aeskey must be 32 characters max.\n'
				quit()
		elif (argv[1][2] == 'l'):
			cur.execute('SELECT nickname, publicname FROM yubikeys')
			if cur.rowcount != 0:
				print " " + str(cur.rowcount) + " keys into database:"
				print '[Nickname]\t\t>> [PublicID]'
				for i in range(0, cur.rowcount):
					(nickname, publicname) = cur.fetchone()
					print ' ' + nickname + ' ' * (23-len(nickname)) + ">> " + publicname
				print ''
			else:
				print 'No keys in database\n'
		else:
			print 'Not enough parameters. Try looking at ' + argv[0] + ' --help'
	elif argv[1][0:2] == '-h':
		if (argv[1][2] == 'd') and (len(argv)>2):
			nickname = re.escape(argv[2])
			cur.execute("SELECT * FROM oathtokens WHERE nickname = '" + nickname + "'")
			if (cur.rowcount == 0):
				print 'Key not found.'
			else:
				cur.execute("SELECT * FROM oathtokens WHERE nickname = '" + nickname + "' AND active = 'true'")
				if (cur.rowcount == 1):
					cur.execute("UPDATE oathtokens SET active = 'false' WHERE nickname = '" + nickname + "'")
					print "Key '" + nickname + "' disabled."
					con.commit()
				else:
					print 'Key is already disabled.'

		elif (argv[1][2] == 'e') and (len(argv)>2):
			nickname = re.escape(argv[2])
			cur.execute("SELECT * FROM oathtokens WHERE nickname = '" + nickname + "'")
			if (cur.rowcount == 0):
				print 'Key not found.'
			else:
				cur.execute("SELECT * FROM oathtokens WHERE nickname = '" + nickname + "' AND active = 'false'")
				if (cur.rowcount == 1):
					cur.execute("UPDATE oathtokens SET active = 'true' WHERE nickname = '" + nickname + "'")
					print "Key '" + nickname + "' enabled."
					con.commit()
				else:
					print 'Key is already enabled.'
		elif (argv[1][2] == 'k') and (len(argv)>2):
			nickname = re.escape(argv[2])
			cur.execute("SELECT * FROM oathtokens WHERE nickname = '" + nickname + "'")
			if (cur.rowcount == 0):
				print 'Key not found.'
			else:
				cur.execute("DELETE FROM oathtokens WHERE nickname = '" + nickname + "'")
				print "Key '" + nickname + "' deleted."
				con.commit()
		elif (argv[1][2] == 'a') and (len(argv)>3):
			nickname = re.escape(argv[2])
			if (len(argv[2])<=16) and (len(argv[3]) <= 16) and (len(argv[4]) <= 40):
				cur.execute("SELECT * FROM oathtokens WHERE nickname = '" + argv[2] + "' OR publicname = '" + argv[3] + "'")
				if (cur.rowcount == 0):
					cur.execute("INSERT INTO oathtokens VALUES ('" + nickname + "', '" + argv[3] + "', '" + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "', '" + argv[4] + "', 'true', 1)")
					con.commit()
					print "Key '" + argv[2] + "' added to database."
				else:
					print 'Key is already into database. Delete it before adding the same key!'
			else:
				print 'Nickname and publicid must be max 16 characters long.'
				print 'Secret key must be 40 characters max.\n'
				quit()
		elif (argv[1][2] == 'l'):
			cur.execute('SELECT nickname, publicname FROM oathtokens')
			if cur.rowcount != 0:
				print " " + str(cur.rowcount) + " keys into database:"
				print '[Nickname]\t\t>> [PublicID]'
				for i in range(0, cur.rowcount):
					(nickname, publicname) = cur.fetchone()
					print ' ' + nickname + ' ' * (23-len(nickname)) + ">> " + publicname
				print ''
			else:
				print 'No keys in database\n'
		else:
			print 'Not enough parameters. Try looking at ' + argv[0] + ' --help'
	elif argv[1][0:2] == '-a':
		if (argv[1][2] == 'a') and (len(argv)>2):
			nickname = re.escape(argv[2])
			cur.execute("SELECT * FROM apikeys WHERE nickname = '" + nickname + "'")
			if (cur.rowcount != 0):
				print 'API Key for this nickname is already present. Remove it or choose another one.\n'
				quit()
			cur.execute('SELECT id FROM apikeys ORDER BY id DESC LIMIT 1')
			if (cur.rowcount != 0):
				id = cur.fetchone()[0] + 1
			else:
				id = 1
			api_key = randomChars(20)
			cur.execute("INSERT INTO apikeys VALUES ('" + nickname + "', '" + api_key + "', '" + str(id) + "')")
			con.commit()
			print "New API Key for '" + nickname + "': '" + api_key.encode('base64').strip() + "'"
			print "Your API Key ID is: " + str(id) + "\n"
		elif (argv[1][2] == 'k') and (len(argv)>2):
			nickname = re.escape(argv[2])
			cur.execute("SELECT * FROM apikeys WHERE nickname = '" + nickname + "'")
			if (cur.rowcount == 0):
				print "API Key for this nickname Doesn't exists!\n"
				quit()
			cur.execute("DELETE FROM apikeys WHERE nickname = '" + nickname + "'")
			con.commit()
			print "API Key for '" + nickname + "' has been deleted.\n"
		elif (argv[1][2] == 'l'):
			cur.execute('SELECT nickname FROM apikeys')
			if cur.rowcount != 0:
				print ' ' + str(cur.rowcount) + ' keys into database:'
				print '[Nickname]'
				for i in range(0, cur.rowcount):
					nickname = cur.fetchone()[0]
					print ' ' + nickname
				print ''
			else:
				print 'No keys in database\n'
			