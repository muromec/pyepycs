import socket
import logging
import random
import hashlib

from epycs.rc4 import RC4

from aes import crypt as aes_crypt
from scrc import calculate32 as calc_scrc32
import struct
import d41

def nonce_hash(data):
    data = '\x00\x00\x00\x00' + data
    assert len(data) == 0x84

    part = hashlib.sha1(data).digest()[:0x10]
    return struct.pack('>4I', *struct.unpack('<4I', part))

class TcpLink(object):

    INIT_PACKED = "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03"
    def __init__(self, addr):
        self.addr = addr
        self.aes_seq = 0
        self.aes_seq_r = 0
        self.aes_sid = 0
        self.aes_key = None
        self.remote_sid = 0

        self.rnd = random.randint(0, 0x10000)
        self.local_rc4 = RC4(self.rnd)

    def connect(self):
        self.con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.con.connect(self.addr)
        initial_data = self.local_rc4.test(self.INIT_PACKED)

        self.send(struct.pack('!L', self.rnd) + initial_data, rc4=False, aes=False)
        response = self.recv(rc4=False, aes=False)
        if len(response) < 14:
            raise IOError('Too short handshake packed')

        [self.remote_iv] = struct.unpack('!L', response[:4])
        self.remote_rc4 = RC4(self.remote_iv)

        logging.info("remote RC4 IV: %x" % self.remote_iv)
 
        handshake_clear = self.remote_rc4.test(response[4:14])

        self.check_handshake(handshake_clear)

        next_size = self.remote_rc4.crypt(response[14:])

        self.check_handshake_2(next_size)

        logging.info('handshake passed with %r' % (self.addr,))

    def check_handshake(self, data):
        pass

    def check_handshake_2(self, data):
        if data[1] == '\x03':
            return

        raise ValueError('RC4 tcp flow handshake failed step 2')

    def aes_enable(self, lnonce, rnonce, lsid, rsid):
        key = nonce_hash(lnonce) + nonce_hash(rnonce)
        sid = (lsid << 16) | rsid
        self.aes_key, self.aes_sid = key, sid

    def send(self, data, rc4=True, aes=True):
        logging.info("raw %s [%x]" % (data.encode('hex'), len(data)))

        if aes:
            data = aes_crypt(data, self.aes_seq, sid=self.aes_sid, key=self.aes_key)
            crc = calc_scrc32(data)
            data += struct.pack('<H', crc ^ self.aes_seq)

            self.aes_seq += 1
            logging.info("encrypted %s [%x]" % (data.encode('hex'), len(data)))


        if aes and True: # first byte correction
            sz = len(data) + 3
            sz *= 2
            sz += 1
            header = d41.encode_to_7bit(sz)
            header.append(5)
            fmt = '<%dB' % len(header)
            str_header = struct.pack(fmt, *header)
            crc = calc_scrc32(data)
            str_header += struct.pack('>H', crc ^ (self.remote_sid<<1))
            data = str_header + data

            logging.info("with header %s [%x]" % (data.encode('hex'), len(data)))

        if rc4:
            data = self.local_rc4.crypt(data)
            logging.info("rc4 %s [%x]" % (data.encode('hex'), len(data)))


        logging.info("send %s [%x]" % (data.encode('hex'), len(data)))
        self.con.sendall(data)

    def recv(self, rc4=True, aes=True):
        data = ''
        self.con.settimeout(2)

        while True:
            try:
                chunk = self.con.recv(4096)
                self.con.settimeout(0.3)
                if not chunk:
                    break
                data += chunk
            except socket.timeout:
                break

        if not data:
            return

        if rc4:
            data = self.remote_rc4.crypt(data)

        if aes:
            # TODO: check size and crc from header
            # oops, losing first 5 bytes
            ct, n = d41.decode_7bit(data[:5])
            # not sure is 5 is fixed offset due to 7bit size encoding
            # XXX: ... and it isn`t.
            # TODO: detect from header, dont guess
            if self.aes_sid:
                skip = 4
                sid = 0xFFFFFFFF ^ self.aes_sid
            else:
                skip = 5
                sid = 0

            data = aes_crypt(data[skip:], self.aes_seq_r, sid=sid, key=self.aes_key)

            self.aes_seq_r += 1

        return data
