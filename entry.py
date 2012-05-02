import sys
from configobj import ConfigObj
import logging
import random
import socket
import struct
from epycs.rc4 import RC4
import d41

class ChatSession(object):
    INIT_PACKED = "\x00\x01\x00\x00\x00\x01\x00\x00\x00\x03"
    INIT_UNK = "\x75\xAA\xBB\xCC\x38\x36\xAA\xBB\x01\xCC\xA9\x02\x28\xDD\xA5\x43\xA5\x15\xA9\xEF\x08"
    def __init__(self, addr):
        self.rnd = random.randint(0, 0x10000)
        self.seq = random.randint(0, 0x10000)
        self.addr = addr
        self.local_rc4 = RC4(self.rnd)

    def connect(self):
        self.con = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.con.connect(self.addr)
        initial_data = self.local_rc4.crypt(self.INIT_PACKED)

        self.send(struct.pack('!L', self.rnd) + initial_data)
        response = self.recv()
        if len(response) < 14:
            raise IOError('Too short handshake packed')

        [self.remote_iv] = struct.unpack('!L', response[:4])
        self.remote_rc4 = RC4(self.remote_iv)
        handshake_clear = self.remote_rc4.test(response[4:14])

        self.check_handshake(handshake_clear)

        next_size = self.remote_rc4.crypt(response[14:])

        self.check_handshake_2(next_size)

        logging.info('handshake passed with %r' % (self.addr,))

    def check_name(self, name):
        # send 6 blobs in single command
        # TODO: move package assemble into d41

        data = d41.format_41_command(6, 0x40DD, 0x43)

        # here are blobs
        data += d41.format_blob(0, 3, 0x259F) # local session id
        data += d41.format_blob(4, 1, self.INIT_UNK)
        data += d41.format_blob(1, 9, (0xF7BB5566, 0xDBDBCE66))
        data += d41.format_blob(0, 0x1B, None) # flag
        data += d41.format_blob(3, 0, unicode(name))
        data += d41.format_blob(0, 0x18, 1) # flag

        print data.encode('hex')

    def send(self, data):
        self.con.sendall(data)

    def recv(self):
        data = self.con.recv(4096)
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

    load()

    chat = ChatSession(addr)
    chat.connect()
    chat.check_name(remote_name)

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)
    main()
