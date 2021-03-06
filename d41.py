import struct
from scrc import calculate as calc_scrc

def encode_to_7bit(word):
    ret = [0]

    while word > 0x7F:
        ret[-1] = (word & 0xFF) | 0x80
        ret.append(word)

        word >>= 7

    ret[-1] = word

    return ret

def decode_7bit(data):
    fmt = '<%dB' % len(data)
    ret = 0
    for n,word in enumerate(struct.unpack(fmt, data)):
        ret |= (word&0x7f) << (n*7)
        if not word & 0x80:
            return ret,n+1

    raise ValueError('All bytes have 0x80 up')

def format_41_command(count, session, cmd):
    ret = encode_to_7bit(session)
    ret.extend([cmd & 0xFF, 0x41, count & 0xFF])

    return struct.pack('<%dB' % len(ret), *ret)

def unpack_41_command(data):
    session,n = decode_7bit(data[:10])
    cmd = ord(data[n+1])
    cmd, fmt, count = struct.unpack_from('<3B', data, n)
    if fmt != 0x41:
        raise ValueError('not 0x41 encoded but %x' % fmt)

    return (session, cmd, count), n +3

def unpack_41_blob(data, blob_pos=0):
    typ, idx = struct.unpack_from('<2B', data, blob_pos)
    blob_pos += 2
    if typ == 0: # int
        val,inc = decode_7bit(data[blob_pos:])
        blob_pos += inc

    elif typ == 1: # 64 bit num
        [val] = struct.unpack_from('<Q', data, blob_pos)
        blob_pos += 8

    else:
        assert typ == 4, "Unknow typ %d" % typ
        sz, inc = decode_7bit(data[blob_pos:])
        blob_pos += inc

        if sz and data[blob_pos] == '\x41':
            fmt, count = struct.unpack_from('<2B', data, blob_pos)
            assert fmt == 0x41
            assert count < 0x100

            blob_pos += 2
            val = {}
            for x in range(count):
                _idx, _val, blob_pos  = unpack_41_blob(data, blob_pos)
                val[_idx] = _val

        else:
            val = data[blob_pos:blob_pos+sz]
            blob_pos += sz

    return idx, val, blob_pos


TYPES = {
        int: 0,
        long: 1,
        unicode: 3,
        str: 4,
        tuple: 1, # XXX packed 64 int
        dict: 4,
        list: 4,
        tuple: 5,
}


def format_blobdict(blobs, header=False):
    assert (
            hasattr(blobs, 'next')
            or isinstance(blobs, (list, tuple))
            or hasattr(blobs, 'iteritems')
    ), "Blobs should support iteration!"

    if isinstance(blobs, dict):
        kv = blobs.iteritems()
    else:
        kv = blobs

    data = ''
    if header:
        data += struct.pack('<2B', 0x41, len(blobs))

    for idx, value in kv:
        data += format_blob(idx, value)

    return data

def format_blob(idx, data):
    # guessing type
    typ = TYPES.get(type(data))
    assert typ is not None, idx

    ret = [0xFF & typ, 0XFF & idx]
    if isinstance(data, (dict, list, tuple)):
        data = format_blobdict(data, header=True)

    if data is None:
        fmt = '<3B' 
        ret.append(0)
        return struct.pack(fmt, *ret)

    elif isinstance(data, int):
        ret.extend(encode_to_7bit(data))

        fmt = '<%dB' % len(ret)

        return struct.pack(fmt, *ret)

    elif isinstance(data, basestring):
        if isinstance(data, unicode):
            data = data.encode('utf8')+'\0'

        sz = len(data)
        if typ in [3,5]:
            pass # maby it`s null-terminated string
        else:
            ret.extend(encode_to_7bit(sz))

        fmt = '<%dB%ds' % (len(ret), len(data))

        ret.append(data)
        return struct.pack(fmt, *ret)
    elif typ == 1: # typ long
        fmt = '<2B'
        fmt2 = '!Q'
        return struct.pack(fmt, *ret) + struct.pack(fmt2, data)

    elif isinstance(data, tuple) and len(data) == 2:
        fmt = '<2B'
        fmt2 = '!2L'
        return struct.pack(fmt, *ret) + struct.pack(fmt2, *data)

class Packet(object):
    def __init__(self, sid=None, cmd=None, blobs=(), raw=None):
        if raw is not None:
            self.raw = raw
            self.decode(raw)
        elif sid and cmd:
            #import random
            #sid = random.randint(1,2**15)
            self.sid, self.cmd, self.blobs = sid, cmd, blobs
            self.encode(sid, cmd, blobs)

    def decode(self, raw):
        # TODO: split into unpack_command and unpack_blobs
        data, off = unpack_41_command(raw)
        self.sid, self.cmd, count = data

        blobs = {}
        for x in range(count):
            idx, val, off = unpack_41_blob(raw, off)
            blobs[idx] = val

        self.blobs = blobs
        assert len(blobs) == count

    def encode(self, sid, cmd, blobs):
        data = format_41_command(len(blobs), sid, cmd)
        data += format_blobdict(blobs)

        data += calc_scrc(data) # not sure, maby move to aes coder
        self.raw = data

    def __repr__(self):
        return '<Pakcet 0x%x sid 0x%04x>' % (self.cmd, self.sid)
