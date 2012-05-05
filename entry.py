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
from utils import h

class ChatSession(object):
    INIT_PACKED = "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03"
    INIT_UNK = unsp.INIT_UNK
    def __init__(self, addr, cred_188):
        self.rnd = random.randint(0, 0x10000)
        self.seq = random.randint(0, 0x10000)
        self.local_sid = int(time.time()) & 0x3FFF
        self.remote_sid = 0
        self.addr = addr
        self.local_rc4 = RC4(self.rnd)
        self.cred_188 = cred_188
        self.aes_seq = 0
        self.aes_seq_r = 0

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
        typ, self.remote_sid = packet.blobs.get(3)

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
            #data = rsa.randnum.read_random_bits(0x80 * 8)
            data = unsp.LOCAL_NONCE
            self._local_nonce = '\x01' + data[1:]

        return self.remote_rsa_crypt(self._local_nonce)

    def remote_rsa_crypt(self, data):
        user = rsa.transform.bytes2int(self.remote_rsa)
        data = rsa.transform.bytes2int(data)
        iret = pow(data, 65537, user)
        return rsa.transform.int2bytes(iret)


    @property
    def aes_key(self):
        if not hasattr(self, 'remote_aes_key'):
            return

        data = unsp.LOCAL_NONCE
        data  = '\x01' + data[1:]
        data = '\x00\x00\x00\x00' + data
        assert len(data) == 0x84

        lpart = hashlib.sha1(data).digest()[:0x10]
        lpart = struct.pack('>4I', *struct.unpack('<4I', lpart))
        rpart = self.remote_aes_key
        return lpart + rpart

    @property
    def aes_sid(self):
        # XXX: look ugly
        if not hasattr(self, 'remote_aes_key'):
            return 0

        return (self.local_sid << 16) | self.remote_sid


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

        packet = d41.Packet(raw=data)
        self.extract_aes_key(packet)

    def join(self, me, remote):
        chatstring = u"#%s/$%s;4fea66013cdd%04d" % (
                me,
                remote,
                random.randint(0,9999)
        )
        out = d41.Packet(0x6406, 0x6D, {
            1: 0x55819F87,
            3: 0,
            4: {
                1: 0xD,
                2: unicode(chatstring),
                0x1c: 1,
                0x1D: 1,
            },
            7: 5,
        })
        self.send(out.raw)
        logging.info("joining char %s" % chatstring)

        out2 = d41.Packet(0x872F, 0x43, {
            0: 0x2a,
            1: u"", # wtf? chat subject?
            2: 0,
        })
        self.send(out2.raw)

        data = self.recv()
        if not data:
            raise IOError("Join failed")

        logging.info("join packet accepted")
        print data.encode('hex')


    def extract_aes_key(self, packet):
        typ, remote_nonce = packet.blobs.get(6)
        clear_remote_nonce = self.cred_188.crypt(remote_nonce)

        # XXX:
        # pretty dumb check, no warranty here,
        # maby should be wiped out as we dont`t know nonce
        # format
        if clear_remote_nonce[0] == '\x01' and \
                clear_remote_nonce[1:16] == clear_remote_nonce[17:32]:
                    logging.info("Remote nonce check passed")
        else:
            raise IOError("Wrong nonce")

        data = '\x00\x00\x00\x00' + clear_remote_nonce
        assert len(data) == 0x84

        aes_key = hashlib.sha1(data).digest()[:0x10]

        # swap endiannes
        self.remote_aes_key = struct.pack('>4I', *struct.unpack('<4I', aes_key))


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
        self.remote_rsa = key


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
            data = aes_crypt(data[5:], self.aes_seq_r)
            self.aes_seq_r += 1

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
    chat.join(config['login'], remote_name)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    main()
