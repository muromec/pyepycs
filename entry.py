import sys
from configobj import ConfigObj
import logging
import random
import socket
import struct
import time
from epycs.rc4 import RC4
import d41
import rsa
import keys
import hashlib
from cred import Cred
from aes import crypt as aes_crypt
from scrc import calculate32 as calc_scrc32
import unsp

class ChatSession(object):
    INIT_PACKED = "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03"
    INIT_UNK = unsp.INIT_UNK
    def __init__(self, addr, cred_188):
        self.rnd = random.randint(0, 0x10000)
        self.seq = random.randint(0, 0x10000)
        self.local_sid = int(time.time()) & 0x3FFF
        self.addr = addr
        self.local_rc4 = RC4(self.rnd)
        self.cred_188 = cred_188
        self.aes_seq = 0

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

    def check_name(self, name):
        # send 6 blobs in single command
        nonce = long(random.randint(0,2**64))

        out = d41.Packet(0x40DD, 0x43, {
            3: self.local_sid,
            0: unicode(name),
            0x1B: 1,
            1: self.INIT_UNK,
            9: nonce,
        })

        self.send(out.raw)

        response = self.recv()
        if not response:
            raise IOError("Connection stalled")

        packet = d41.Packet(raw=response)
        self.extract_key(packet)

        typ, challenge = packet.blobs.get(0xa)
        typ, self.remote_nonce = packet.blobs.get(9, (None,None))

    @property
    def challenge_response(self):
        nonce = struct.pack('>Q', self.remote_nonce)
        nonce += '\x01'

        nonce_hash = hashlib.sha1(nonce)
        data = unsp.CHALLENGE[:0x62]
        data += nonce
        data += nonce_hash.digest()
        data += '\xBC'

        assert len(data) == 0x80, len(data)

        return self.cred_188.crypt(data)

    @property
    def local_nonce(self):
        if not hasattr(self, '_local_nonce'):
            data = rsa.randnum.read_random_bits(0x80 * 8)
            self._local_nonce = '\x01' + data[1:]

        return self.cred_188.crypt(self._local_nonce)

    @property
    def aes_key(self):
        data = '\x00\x00\x00\x00' + self.local_nonce
        assert len(data) == 0x84

        return hashlib.sha1(data).digest()[:0x10]


    def send_nonce(self,):

        out = d41.Packet(0x44EF, 0x45, {
            0x16: 1,
            0x1A: 1,
            2: 0x5F359B29,
            5: self.cred_188.raw,
            0xD: 2,
            0xA: self.challenge_response,
            0x19: 1,
            6: self.local_nonce,
            0x11: unsp.LOCAL_UIC,
            0x14: 0,
        })
        self.send(out.raw)

        data = self.recv()
        if not data:
            raise IOError('Empty response in nonce')



    def extract_key(self, packet):
        typ, val = packet.blobs.get(5, (None,None))

        skype_pub = rsa.transform.bytes2int(keys.SKYPE_PUB)
        user = rsa.transform.bytes2int(val[8:0x108])

        cred = pow(user, 65537, skype_pub)
        cred = rsa.transform.int2bytes(cred)
        key_start = cred.find('\x80\x01')
        if key_start < 0:
            raise ValueError('cant find key in creds')

        key_start += 2
        key = cred[key_start:key_start+0x80]
        logging.info("extraced user key %s" % key.encode('hex'))


    def send(self, data, rc4=True, aes=True):
        logging.info("raw %s [%x]" % (data.encode('hex'), len(data)))

        if aes:
            data = aes_crypt(data, self.aes_seq)
            self.aes_seq += 1
            data += struct.pack('<H', calc_scrc32(data))
            logging.info("encrypted %s [%x]" % (data.encode('hex'), len(data)))

        if aes and True: # first byte correction
            sz = len(data) + 3
            sz *= 2
            sz += 1
            header = d41.encode_to_7bit(sz)
            header.append(5)
            fmt = '<%dB' % len(header)
            str_header = struct.pack(fmt, *header)
            str_header += struct.pack('>H', calc_scrc32(data))
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
            data = aes_crypt(data[5:])

        return data

    def check_handshake(self, data):
        pass

    def check_handshake_2(self, data):
        if data[1] == '\x03':
            return

        raise ValueError('RC4 tcp flow handshake failed step 2')

def load(fname='epycs.conf'):
    config = ConfigObj(fname)

    KEYS = [
            'login',
            'password',
            'fullname',
            'email',
            'version',
            'cred',
            'cred_p',
            'cred_q',
    ]

    for key in KEYS:
        if key not in config:
            print 'oops %s missing from config' % key
            sys.exit(1)

    return config

def main():
    if len(sys.argv) < 3:
        print 'Specify peer login and address'
        sys.exit(1)

    remote_name, addr = sys.argv[1:3]
    if ':' in addr:
        addr = addr.split(':', 1)
        addr = addr[0], int(addr[1])
    else:
        addr = addr, 60331

    msg = sys.argv[3] if len(sys.argv) > 3 else 'Wake up, Neo ^_^'

    logging.info('about to send %r to user %s at addr %r' % (msg, remote_name, addr))

    config = load()

    cred_188 = Cred(config)
    logging.debug("compuped cred_188 %s" % cred_188.raw.encode('hex'))

    chat = ChatSession(addr, cred_188)

    chat.connect()
    chat.check_name(remote_name)
    chat.send_nonce()

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    main()
