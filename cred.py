import hashlib
import rsa
import unsp

class Cred(object):
    INIT_UNK = unsp.INIT_UNK

    def __init__(self, config):
        self.config = config

    @property
    def raw(self):

        # 4-byte header
        # 0x104 bytes of cred
        # 0x80 bytes of signed after cred
        ret = "\x00\x00\x01\x04"
        ret += self.cred
        ret += self.after_cred

        assert len(ret) == 0x188, hex(len(ret))

        return ret

    @property
    def after_cred(self):
        ret = '\x4b'+('\xbb'*0x3b)+'\xba' # ya! really!
        cred_hash = hashlib.sha1(self.cred)
        digest = cred_hash.digest()
        digest += '\x41\x01\x04\x03\x15' # 41?
        digest += self.INIT_UNK
        ret += digest
        ret += hashlib.sha1(digest).digest()
        ret += '\xbc'

        return self.crypt(ret)

    def crypt(self, data):
        iret = rsa.transform.bytes2int(data)

        signed = pow(iret, self.user_priv, self.user_pub)
        assert len(rsa.transform.int2bytes(signed)) == 0x80
        return rsa.transform.int2bytes(signed)

    @property
    def user_priv(self):
        ret = self.config['user_priv'].replace(' ', '')
        ret = ret.decode('hex')
        return rsa.transform.bytes2int(ret)

    @property
    def user_pub(self):
        ret = self.config['user_pub'].replace(' ','')
        ret = ret.decode('hex')
        return rsa.transform.bytes2int(ret)

    @property
    def cred(self):
        # 4-byte header
        # 0x100 bytes of user cred (config['cred'])
        cred = self.config['cred']

        ret = cred.decode('hex')

        return ret
