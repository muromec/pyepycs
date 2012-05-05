import sys
from configobj import ConfigObj
import logging
import random
import struct
import time
import d41
import rsa
import keys
import hashlib
from cred import Cred
import unsp
import net

class ChatSession(object):
    INIT_UNK = unsp.INIT_UNK
    def __init__(self, addr, cred_188):
        self.local_sid = int(time.time()) & 0x3FFF
        self.addr = addr
        self.cred_188 = cred_188

        lnonce = rsa.randnum.read_random_bits(0x80 * 8)
        self._lnonce = '\x01' + lnonce[1:]

        self.link = net.TcpLink(addr)

        # XXX
        self.send = self.link.send
        self.recv = self.link.recv

    def connect(self):
        self.link.connect()
       
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

        [response] = self.recv()
        if not response:
            raise IOError("Connection stalled")

        packet = d41.Packet(raw=response)
        self.extract_remote_pub(packet)

        typ, challenge = packet.blobs.get(0xa)
        typ, self.remote_nonce = packet.blobs.get(9, (None,None))
        typ, self.link.remote_sid = packet.blobs.get(3)

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
        return self.remote_rsa_crypt(self._lnonce)

    def remote_rsa_crypt(self, data):
        user = rsa.transform.bytes2int(self.remote_rsa)
        data = rsa.transform.bytes2int(data)
        iret = pow(data, 65537, user)
        return rsa.transform.int2bytes(iret)


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

        [data] = self.recv()
        if not data:
            raise IOError('Empty response in nonce')

        packet = d41.Packet(raw=data)
        self.extract_aes_key(packet)

    def join(self, me, remote):
        self.chatstring = u"#%s/$%s;4fea66013cdd%04d" % (
                me,
                remote,
                random.randint(0,9999)
        )
        out = d41.Packet(0x6406, 0x6D, {
            1: 0x55819F87,
            3: 0,
            4: {
                1: 0xD,
                2: unicode(self.chatstring),
                0x1c: 1,
                0x1D: 1,
            },
            7: 5,
        })
        self.send(out.raw)
        logging.info("joining char %s" % self.chatstring)

        out2 = d41.Packet(0x872F, 0x43, {
            0: 0x2a,
            1: u"", # wtf? chat subject?
            2: 0,
        })
        self.send(out2.raw)

        for data in self.recv():
            if not data:
                raise IOError("Join failed")

            packet = d41.Packet(raw=data)
            print packet, packet.blobs

    def post_join(self):
        cred = None
        chat_names = ""
        newblk = None

        # ZOMG1111
        out = d41.Packet(0xAA58, 0x6D, {
            1: 0x55819F87,
            3: 1,
            4: {
                1: 0x24,
                2: unicode(self.chatstring),
                0x1b: 7,
                0x12: chat_names,
                0x1e: 0,
                0x19: [
                    (0, [
                        (0,8),
                        (1,1),
                        (2, 0xE9C261A9),
                        (3, newblk),
                        (4, cred),
                    ]),
                    (6, 1),
                    (7, 0x08DD791A),
                    (9, 0x013AF2C7),
                ],
            },
        })


    def extract_aes_key(self, packet):
        typ, remote_nonce = packet.blobs.get(6)
        rnonce = self.cred_188.crypt(remote_nonce)

        self.link.aes_enable(self._lnonce, rnonce, self.local_sid, self.link.remote_sid)


    def extract_remote_pub(self, packet):
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
