import struct

def encode_to_7bit(word):
    ret = [0]

    while word > 0x7F:
        ret[-1] = (word & 0xFF) | 0x80
        ret.append(word)

        word >>= 7

    ret[-1] = word

    return ret

def format_41_command(count, session, cmd):
    ret = encode_to_7bit(session)
    ret.extend([cmd & 0xFF, 0x41, count & 0xFF])

    return struct.pack('<%dB' % len(ret), *ret)

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
