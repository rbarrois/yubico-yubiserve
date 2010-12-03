#!/usr/bin/python
import sqlite, re, os, time
import urlparse, SocketServer, urllib, BaseHTTPServer
from Crypto.Cipher import AES
import hmac, hashlib

yubiservePORT = 8000
yubiserveHOST = '0.0.0.0'	# You can use '127.0.0.1' to avoid
							# the server to receive queries from
							# the outside

class OATHValidation():
	status = {'OK': 1, 'BAD_OTP': 2, 'NO_AUTH': 3, 'NO_CLIENT': 5}
	validationResult = 0
	def testHOTP(self, K, C, digits=6):
		counter = ("%x"%C).rjust(16,'0').decode('hex') # Convert it into 8 bytes hex
		HS = hmac.new(K, counter, hashlib.sha1).digest()
		offset = ord(HS[19]) & 0xF
		# It doesn't look pretty, but it is optimized! :D
		bin_code = int((chr(ord(HS[offset]) & 0x7F) + HS[offset+1:offset+4]).encode('hex'),16)
		return str(bin_code)[-digits:]
	def validateOATH(self, OATH, publicID):
		con = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite')
		cur = con.cursor()
		cur.execute("SELECT counter, secret FROM oathtokens WHERE publicname = '" + publicID + "' AND active = 'true'")
		if (cur.rowcount != 1):
			validationResult = self.status['BAD_OTP']
			return validationResult
		(actualcounter, key) = cur.fetchone()
		
		if len(OATH) % 2 != 0:
			self.validationResult = self.status['BAD_OTP']
			return self.validationResult
		K = key.decode('hex') # key
		for C in range(actualcounter+1, actualcounter+256):
			if OATH == self.testHOTP(K, C, len(OATH)):
				cur.execute("UPDATE oathtokens SET counter = " + str(C) + " WHERE publicname = '" + publicID + "' AND active = 'true'")
				con.commit()
				return self.status['OK']
		return self.status['NO_AUTH']

class OTPValidation():
	status = {'OK': 1, 'BAD_OTP': 2, 'REPLAYED_OTP': 3, 'DELAYED_OTP': 4, 'NO_CLIENT': 5}
	validationResult = 0
	
	def hexdec(self, hex):
		return int(hex, 16)
	def modhex2hex(self, string):
		hex = "0123456789abcdef"
		modhex = "cbdefghijklnrtuv"
		retVal = ''
		for i in range (0, len(string)):
			pos = modhex.find(string[i])
			if pos > -1:
				retVal += hex[pos]
			else:
				raise Exception, '"' + string[i] + '": Character is not a valid hex string'
		return retVal
	def CRC(self):
		crc = 0xffff;
		for i in range(0, 16):
			b = self.hexdec(self.plaintext[i*2] + self.plaintext[(i*2)+1])
			for j in range(0, 8):
				n = crc & 1
				crc = crc >> 1
				if n != 0:
					crc = crc ^ 0x8408
		self.OTPcrc = crc
		return [crc]
	def isCRCValid(self):
		return (self.crc == 0xf0b8)
	def aes128ecb_decrypt(self, aeskey, aesdata):
		return AES.new(aeskey.decode('hex'), AES.MODE_ECB).decrypt(aesdata.decode('hex')).encode('hex')
	def getResult(self):
		return self.validationResult
	def getResponse(self):
		return self.validationResponse
	def validateOTP(self, OTP):
		self.OTP = re.escape(OTP)
		self.validationResult = 0
		if (len(OTP) <= 32) or (len(OTP) > 48):
			self.validationResult = self.status['BAD_OTP']
			return self.validationResult
		match = re.search('([cbdefghijklnrtuv]{0,16})([cbdefghijklnrtuv]{32})', re.escape(OTP))
		try:
			if match.group(1) and match.group(2):
				self.userid = match.group(1)
				self.token = self.modhex2hex(match.group(2))
				con = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite')
				cur = con.cursor()
				cur.execute('SELECT aeskey, internalname FROM yubikeys WHERE publicname = "' + self.userid + '" AND active = "true"')
				if (cur.rowcount != 1):
					print "1"
					self.validationResult = self.status['BAD_OTP']
					con.close()
					return self.validationResult
				(self.aeskey, self.internalname) = cur.fetchone()
				self.plaintext = self.aes128ecb_decrypt(self.aeskey, self.token)
				uid = self.plaintext[:12]
				if (self.internalname != uid):
					print "2"
					self.validationResult = self.status['BAD_OTP']
					con.close()
					return self.validationResult
				if not (self.CRC() or self.isCRCValid()):
					print "3"
					self.validationResult = self.status['BAD_OTP']
					con.close()
					return self.validationResult
				self.internalcounter = self.hexdec(self.plaintext[14:16] + self.plaintext[12:14] + self.plaintext[22:24])
				self.timestamp = self.hexdec(self.plaintext[20:22] + self.plaintext[18:20] + self.plaintext[16:18])
				cur.execute('SELECT counter, time FROM yubikeys WHERE publicname = "' + self.userid + '" AND active = "true"')
				if (cur.rowcount != 1):
					print "4"
					self.validationResult = self.status['BAD_OTP']
					con.close()
					return self.validationResult
				(self.counter, self.time) = cur.fetchone()
				if (self.counter) >= (self.internalcounter):
					self.validationResult = self.status['REPLAYED_OTP']
					con.close()
					return self.validationResult
				if (self.time >= self.timestamp) and ((self.counter >> 8) == (self.internalcounter >> 8)):
					self.validationResult = self.status['DELAYED_OTP']
					con.close()
					return self.validationResult
		except IndexError:
			print "5"
			self.validationResult = self.status['BAD_OTP']
			con.close()
			return self.validationResult
		self.validationResult = self.status['OK']
		cur.execute('UPDATE yubikeys SET counter = ' + str(self.internalcounter) + ', time = ' + str(self.timestamp) + ' WHERE publicname = "' + self.userid + '"')
		con.commit()
		con.close()
		return self.validationResult

class Yubiserve (BaseHTTPServer.BaseHTTPRequestHandler):
	__base = BaseHTTPServer.BaseHTTPRequestHandler
	__base_handle = __base.handle
	server_version = 'Yubiserve/2.0'
	print 'HTTP Server is running.'

	def getToDict(self, qs):
		dict = {}
		for singleValue in qs.split('&'):
			keyVal = singleValue.split('=')
			dict[urllib.unquote_plus(keyVal[0])] = urllib.unquote_plus(keyVal[1])
		return dict
	def log_message(self, format, *args):
		pass
	def do_GET(self):
		(scm, netloc, path, params, query, fragment) = urlparse.urlparse(self.path, 'http')
		if scm != 'http':
			self.send_error(501, "The server does not support the facility required.")
			return
		if (path != '/wsapi/2.0/verify') and (path != '/wsapi/2.0/oathverify'):
			self.send_response(200)
			self.send_header('Content-type', 'text/html')
			self.end_headers()
			self.wfile.write('<html>')
			# Yubico Yubikey
			self.wfile.write('Yubico Yubikeys:<br><form action="/wsapi/2.0/verify" method="GET"><input type="text" name="otp"><br><input type="submit"></form><br>')
			# OATH HOTP
			self.wfile.write('OATH/HOTP tokens:<br><form action="/wsapi/2.0/oathverify" method="GET"><input type="text" name="otp"><br><input type="text" name="publicid"><br><input type="submit"></form>')
			self.wfile.write('</html>')
		elif path == '/wsapi/2.0/verify': # Yubico Yubikey
			try:
				if len(query) > 0:
					getData = self.getToDict(query)
					otpvalidation = OTPValidation()
					validation = otpvalidation.validateOTP(getData['otp'])
					self.send_response(200)
					self.send_header('Content-type', 'text/plain')
					self.end_headers()
					iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
					try:
						result = 't=' + iso_time + '\r\notp=' + getData['otp'] + '\r\nnonce=' + getData['nonce'] + '\r\nsl=100\r\nstatus=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '\r\n'
					except KeyError:
						result = 't=' + iso_time + '\r\notp=' + getData['otp'] + '\r\nnonce=\r\nsl=100\r\nstatus=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '\r\n'
					otp_hmac = ''
					try:
						if (getData['id'] != None):
							apiID = re.escape(getData['id'])
							con = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite')
							cur = con.cursor()
							cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
							if cur.rowcount != 0:
								api_key = cur.fetchone()[0]
								otp_hmac = hmac.new(api_key.decode('base64'), msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
							else:
								result = 't=' + iso_time + '\r\notp=' + getData['otp'] + '\r\nstatus=NO_CLIENT\r\n'
					except KeyError:
						pass
					self.wfile.write('h=' + otp_hmac + '\r\n' + result + '\r\n')
					return
			except KeyError:
				pass
			self.send_response(200)
			self.send_header('Content-type', 'text/plain')
			self.end_headers()
			iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
			try:
				result = 't=' + iso_time + '\r\notp=\r\nnonce=\r\nstatus=MISSING_PARAMETER\r\n'
			except KeyError:
					result = 't=' + iso_time + '\r\notp=\r\nnonce=\r\nstatus=MISSING_PARAMETER\r\n'
			otp_hmac = ''
			try:
				if (getData['id'] != None):
					apiID = re.escape(getData['id'])
					con = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite')
					cur = con.cursor()
					cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
					if cur.rowcount != 0:
						api_key = cur.fetchone()[0]
						otp_hmac = hmac.new(api_key.decode('base64'), msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
			except KeyError:
				pass
			self.wfile.write('h=' + otp_hmac + '\r\n' + result + '\r\n')
			return
		elif path == '/wsapi/2.0/oathverify': # OATH HOTP
			try:
				getData = self.getToDict(query)
				if (len(query) > 0) and ((len(getData['otp']) == 6) or (len(getData['otp']) == 8) or (len(getData['otp']) == 18) or (len(getData['otp']) == 20)):
					oathvalidation = OATHValidation()
					OTP = getData['otp']
					if (len(OTP) == 18) or (len(OTP) == 20):
						publicID = OTP[0:12]
						OTP = OTP[12:]
					elif (len(OTP) == 6) or (len(OTP) == 8):
						if len(getData['publicid'])>0:
							publicID = getData['publicid']
						else:
							raise KeyError
					
					validation = oathvalidation.validateOATH(OTP, publicID)
					self.send_response(200)
					self.send_header('Content-type', 'text/plain')
					self.end_headers()
					iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
					result = 'otp=' + getData['otp'] + '\r\nstatus=' + [k for k, v in oathvalidation.status.iteritems() if v == validation][0] + '\r\nt=' + iso_time
					otp_hmac = ''
					try:
						if (getData['id'] != None):
							apiID = re.escape(getData['id'])
							con = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite')
							cur = con.cursor()
							cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
							if cur.rowcount != 0:
								api_key = cur.fetchone()[0]
								otp_hmac = hmac.new(api_key.decode('base64'), msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
							else:
								result = 'otp=' + getData['otp'] + '\r\nstatus=NO_CLIENT\r\nt=' + iso_time
					except KeyError:
						pass
					self.wfile.write(result + '\nh=' + otp_hmac)
					return
				else:
					self.send_response(200)
					self.send_header('Content-type', 'text/plain')
					self.end_headers()
					iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
					result = 'otp=\r\nstatus=BAD_OTP\r\nt=' + iso_time
					otp_hmac = ''
					try:
						if (getData['id'] != None):
							apiID = re.escape(getData['id'])
							con = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite')
							cur = con.cursor()
							cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
							if cur.rowcount != 0:
								api_key = cur.fetchone()[0]
								otp_hmac = hmac.new(api_key.decode('base64'), msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
					except KeyError:
						pass
					self.wfile.write('h=' + otp_hmac + '\n' + result)
					return
			except KeyError:
				pass
			self.send_response(200)
			self.send_header('Content-type', 'text/plain')
			self.end_headers()
			iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
			result = 'otp=\r\nstatus=MISSING_PARAMETER\r\nt=' + iso_time
			otp_hmac = ''
			try:
				if (getData['id'] != None):
					apiID = re.escape(getData['id'])
					con = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite')
					cur = con.cursor()
					cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
					if cur.rowcount != 0:
						api_key = cur.fetchone()[0]
						otp_hmac = hmac.new(api_key.decode('base64'), msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
			except KeyError:
				pass
			self.wfile.write('h=' + otp_hmac + '\n' + result)
			return
	do_HEAD		= do_GET
	do_PUT		= do_GET
	do_DELETE	= do_GET
	do_CONNECT	= do_GET
	do_POST		= do_GET

class ThreadingHTTPServer (SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer): pass

yubiserve = ThreadingHTTPServer((yubiserveHOST, yubiservePORT), Yubiserve)
try:
	yubiserve.serve_forever()
except KeyboardInterrupt:
	print ""
	yubiserve.server_close()
