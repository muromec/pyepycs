import struct

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
        raise ValueError('not 0x41 encoded')

    ret = {}

    blob_pos = n+3
    for x in range(count):
        typ, idx = struct.unpack_from('<2B', data, blob_pos)
        blob_pos += 2
        if typ == 0: # int
            val,inc = decode_7bit(data[blob_pos:])
            blob_pos += inc

            ret[idx] = (typ, val)

        elif typ == 1: # two 64 bit nums
            val = struct.unpack_from('!2L', data, blob_pos)
            blob_pos += 8
            ret[idx] = (typ, val)

        else:
            assert typ == 4, "Unknow typ %d" % typ
            sz, inc = decode_7bit(data[blob_pos:])
            blob_pos += inc
            val = data[blob_pos:blob_pos+sz]
            blob_pos += sz
            ret[idx] = (typ, val)


    # TODO: last 4 bytes CRC
    return ret


def format_blob(typ, idx, data):
    ret = [0xFF & typ, 0XFF & idx]
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
    elif isinstance(data, tuple) and len(data) == 2:
        fmt = '<2B'
        fmt2 = '!2L'
        return struct.pack(fmt, *ret) + struct.pack(fmt2, *data)
