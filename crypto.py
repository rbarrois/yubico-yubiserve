# coding: utf-8


class OATHValidator(object):
    STATUS_OK = 'OK'
    STATUS_BAD = 'BAD'
    STATUS_NO_AUTH = 'NO_AUTH'
    STATUS_NO_CLIENT = 'NO_CLIENT'

    def __init__(self, dbread_callback, dbwrite_callback):
        self.dbread_callback = dbread_callback
        self.dbwrite_callback = dbwrite_callback

    def test_HOTP(self, K, C, digits=6):
        counter = ('%s' % C).rjust(16, '0').decode('hex')
        HS = hmac.new(K, counter, hashlib.sha1).digest()
        offset = ord(HS[19]) & 0xF
        bin_code = int((chr(ord(HS[offset]) & 0x7F) + HS[offset+1:offset+4]).encode('hex'), 16)
        return str(bin_code)[-digits:]

    def validate_OATH(self, OATH, publicID):
        if len(OATH) % 2 != 0:
            return self.STATUS_BAD

        token_data = self.dbread_callback(publicID=publicID)
        if token_data.rowcount != 1:
            return self.STATUS_BAD

        (actualcounter, key) = token_data.fetchone()

        K = key.decode('hex')
        for C in range(actualcounter + 1, actualcounter + 256):
            if OATH == self.test_HOTP(K, C, len(OATH)):
                self.dbwrite_callback(counter=str(C), publicID=publicID)
                return self.STATUS_OK

        return self.STATUS_NO_AUTH
