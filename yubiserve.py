#!/usr/bin/python
# coding: utf-8

import BaseHTTPServer
import SocketServer
import hashlib
import hmac
import os
import re
import socket
import time
import urllib
import urlparse

from threading import Thread
from Crypto.Cipher import AES
from OpenSSL import SSL

try:
    import MySQLdb
except ImportError:
    pass
try:
    import sqlite
except ImportError:
    pass

def parseConfigFile():  # Originally I wrote this function to parse PHP configuration files!
    config = open(os.path.dirname(os.path.realpath(__file__)) + '/yubiserve.cfg', 'r').read().splitlines()
    keys = {}
    for line in config:
        match = re.search('(.*?)=(.*);', line)
        try: # Check if it's a string or a number
            if ((match.group(2).strip()[0] != '"') and (match.group(2).strip()[0] != '\'')):
                keys[match.group(1).strip()] = int(match.group(2).strip())
            else:
                keys[match.group(1).strip()] = match.group(2).strip('"\' ')
        except:
            pass
    return keys

config = parseConfigFile()

class OATHValidation():
    def __init__(self, connection):
        self.status = {'OK': 1, 'BAD_OTP': 2, 'NO_AUTH': 3, 'NO_CLIENT': 5}
        self.validationResult = 0
        self.con = connection
    def testHOTP(self, K, C, digits=6):
        counter = ("%x"%C).rjust(16,'0').decode('hex') # Convert it into 8 bytes hex
        HS = hmac.new(K, counter, hashlib.sha1).digest()
        offset = ord(HS[19]) & 0xF
        # It doesn't look pretty, but it is optimized! :D
        bin_code = int((chr(ord(HS[offset]) & 0x7F) + HS[offset+1:offset+4]).encode('hex'),16)
        return str(bin_code)[-digits:]
    def validateOATH(self, OATH, publicID):
        cur = self.con.cursor()
        cur.execute("SELECT counter, secret FROM oathtokens WHERE publicname = '" + publicID + "' AND active = '1'")
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
                cur.execute("UPDATE oathtokens SET counter = " + str(C) + " WHERE publicname = '" + publicID + "' AND active = '1'")
                self.con.commit()
                return self.status['OK']
        return self.status['NO_AUTH']

class OTPValidation():
    def __init__(self, connection):
        self.status = {'OK': 1, 'BAD_OTP': 2, 'REPLAYED_OTP': 3, 'DELAYED_OTP': 4, 'NO_CLIENT': 5}
        self.validationResult = 0
        self.con = connection
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
                cur = self.con.cursor()
                cur.execute('SELECT aeskey, internalname FROM yubikeys WHERE publicname = "' + self.userid + '" AND active = "1"')
                if (cur.rowcount != 1):
                    self.validationResult = self.status['BAD_OTP']
                    return self.validationResult
                (self.aeskey, self.internalname) = cur.fetchone()
                self.plaintext = self.aes128ecb_decrypt(self.aeskey, self.token)
                uid = self.plaintext[:12]
                if (self.internalname != uid):
                    self.validationResult = self.status['BAD_OTP']
                    return self.validationResult
                if not (self.CRC() or self.isCRCValid()):
                    self.validationResult = self.status['BAD_OTP']
                    return self.validationResult
                self.internalcounter = self.hexdec(self.plaintext[14:16] + self.plaintext[12:14] + self.plaintext[22:24])
                self.timestamp = self.hexdec(self.plaintext[20:22] + self.plaintext[18:20] + self.plaintext[16:18])
                cur.execute('SELECT counter, time FROM yubikeys WHERE publicname = "' + self.userid + '" AND active = "1"')
                if (cur.rowcount != 1):
                    self.validationResult = self.status['BAD_OTP']
                    return self.validationResult
                (self.counter, self.time) = cur.fetchone()
                if (self.counter) >= (self.internalcounter):
                    self.validationResult = self.status['REPLAYED_OTP']
                    return self.validationResult
                if (self.time >= self.timestamp) and ((self.counter >> 8) == (self.internalcounter >> 8)):
                    self.validationResult = self.status['DELAYED_OTP']
                    return self.validationResult
        except IndexError:
            self.validationResult = self.status['BAD_OTP']
            return self.validationResult
        self.validationResult = self.status['OK']
        cur.execute('UPDATE yubikeys SET counter = ' + str(self.internalcounter) + ', time = ' + str(self.timestamp) + ' WHERE publicname = "' + self.userid + '"')
        self.con.commit()
        return self.validationResult

class YubiServeHandler (BaseHTTPServer.BaseHTTPRequestHandler):
    __base = BaseHTTPServer.BaseHTTPRequestHandler
    __base_handle = __base.handle
    server_version = 'Yubiserve/3.0'
    global config
    #try:
    if config['yubiDB'] == 'sqlite':
        con = sqlite.connect(os.path.dirname(os.path.realpath(__file__)) + '/yubikeys.sqlite')
    elif config['yubiDB'] == 'mysql':
        con = MySQLdb.connect(host=config['yubiMySQLHost'], user=config['yubiMySQLUser'], passwd=config['yubiMySQLPass'], db=config['yubiMySQLName'])
    #except:
    #   print "There's a problem with the database!\n"
    #   quit()

    def getToDict(self, qs):
        dict = {}
        for singleValue in qs.split('&'):
            keyVal = singleValue.split('=')
            dict[urllib.unquote_plus(keyVal[0])] = urllib.unquote_plus(keyVal[1])
        return dict
    def setup(self):
        self.connection = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)
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
                    otpvalidation = OTPValidation(self.con)
                    validation = otpvalidation.validateOTP(getData['otp'])
                    self.send_response(200)
                    self.send_header('Content-type', 'text/plain')
                    self.end_headers()
                    iso_time = time.strftime("%Y-%m-%dT%H:%M:%S")
                    try:
                        result = 't=' + iso_time + '\r\notp=' + getData['otp'] + '\r\nnonce=' + getData['nonce'] + '\r\nsl=100\r\nstatus=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '\r\n'
                        orderedResult = 'nonce=' + getData['nonce'] + '&otp=' + getData['otp'] + '&sl=100&status=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '&t=' + iso_time
                    except KeyError:
                        result = 't=' + iso_time + '\r\notp=' + getData['otp'] + '\r\nnonce=\r\nsl=100\r\nstatus=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '\r\n'
                        orderedResult = 'nonce=&otp=' + getData['otp'] + 'sl=100&status=' + [k for k, v in otpvalidation.status.iteritems() if v == validation][0] + '&t=' + iso_time
                    otp_hmac = ''
                    try:
                        if (getData['id'] != None):
                            apiID = re.escape(getData['id'])
                            cur = self.con.cursor()
                            cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
                            if cur.rowcount != 0:
                                api_key = cur.fetchone()[0]
                                otp_hmac = hmac.new(api_key, msg=orderedResult, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
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
            result = 't=' + iso_time + '\r\notp=\r\nnonce=\r\nstatus=MISSING_PARAMETER\r\n'
            orderedResult = 'nonce=&otp=&status=MISSING_PARAMETER&t=' + iso_time
            otp_hmac = ''
            try:
                if (getData['id'] != None):
                    apiID = re.escape(getData['id'])
                    cur = self.con.cursor()
                    cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
                    if cur.rowcount != 0:
                        api_key = cur.fetchone()[0]
                        otp_hmac = hmac.new(api_key, msg=orderedResult, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
            except KeyError:
                pass
            self.wfile.write('h=' + otp_hmac + '\r\n' + result + '\r\n')
            return
        elif path == '/wsapi/2.0/oathverify': # OATH HOTP
            try:
                getData = self.getToDict(query)
                if (len(query) > 0) and ((len(getData['otp']) == 6) or (len(getData['otp']) == 8) or (len(getData['otp']) == 18) or (len(getData['otp']) == 20)):
                    oathvalidation = OATHValidation(self.con)
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
                            cur = self.con.cursor()
                            cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
                            if cur.rowcount != 0:
                                api_key = cur.fetchone()[0]
                                otp_hmac = hmac.new(api_key, msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
                            else:
                                result = 'otp=' + getData['otp'] + '\r\nstatus=NO_CLIENT\r\nt=' + iso_time
                    except KeyError:
                        pass
                    self.wfile.write(result + '\r\nh=' + otp_hmac)
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
                            cur = self.con.cursor()
                            cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
                            if cur.rowcount != 0:
                                api_key = cur.fetchone()[0]
                                otp_hmac = hmac.new(api_key, msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
                    except KeyError:
                        pass
                    self.wfile.write('h=' + otp_hmac + '\r\n' + result)
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
                    cur = self.con.cursor()
                    cur.execute("SELECT secret from apikeys WHERE id = '" + apiID + "'")
                    if cur.rowcount != 0:
                        api_key = cur.fetchone()[0]
                        otp_hmac = hmac.new(api_key, msg=result, digestmod=hashlib.sha1).hexdigest().decode('hex').encode('base64').strip()
            except KeyError:
                pass
            self.wfile.write('h=' + otp_hmac + '\r\n' + result)
            return
    do_HEAD     = do_GET
    do_PUT      = do_GET
    do_DELETE   = do_GET
    do_CONNECT  = do_GET
    do_POST     = do_GET

class SecureHTTPServer(BaseHTTPServer.HTTPServer):
    def __init__(self, server_address, HandlerClass):
        BaseHTTPServer.HTTPServer.__init__(self, server_address, HandlerClass)
        ctx = SSL.Context(SSL.SSLv23_METHOD)
        fpem = os.path.dirname(os.path.realpath(__file__)) + '/yubiserve.pem'
        ctx.use_privatekey_file (fpem)
        ctx.use_certificate_file(fpem)
        self.socket = SSL.Connection(ctx, socket.socket(self.address_family, self.socket_type))
        self.server_bind()
        self.server_activate()

class ThreadingHTTPServer (SocketServer.ThreadingMixIn, BaseHTTPServer.HTTPServer): pass
class ThreadingHTTPSServer (SocketServer.ThreadingMixIn, SecureHTTPServer): pass

try:
    if MySQLdb != None:
        isThereMysql = True
except NameError:
    isThereMysql = False
try:
    if sqlite != None:
        isThereSqlite = True
except NameError:
    isThereSqlite = False
if isThereMysql == isThereSqlite == False:
    print "Cannot continue without any database support.\nPlease read README.\n\n"
    quit()
if config['yubiDB'] == 'mysql' and (config['yubiMySQLHost'] == '' or config['yubiMySQLUser'] == '' or config['yubiMySQLPass'] == '' or config['yubiMySQLName'] == ''):
    print "Cannot continue without any MySQL configuration.\nPlease read README.\n\n"
    quit()

yubiserveHTTP = ThreadingHTTPServer((config['yubiserveHOST'], config['yubiservePORT']), YubiServeHandler)
yubiserveSSL = ThreadingHTTPSServer((config['yubiserveHOST'], config['yubiserveSSLPORT']), YubiServeHandler)

http_thread = Thread(target=yubiserveHTTP.serve_forever)
ssl_thread = Thread(target=yubiserveSSL.serve_forever)

http_thread.setDaemon(True)
ssl_thread.setDaemon(True)

http_thread.start()
ssl_thread.start()

print "HTTP Server is running."

while 1:
    time.sleep(1)
