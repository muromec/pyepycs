import struct
from epycs.aes import AES

def crypt(data, blk_seq=0, sid=0):
    aes = AES('\x00'*0x20)
    sz = len(data)

    seq = blk_seq * 0x10000

    ret = []
    pos = 0
    while sz > (pos + 16):
        pt_data = struct.pack('<4L', sid, 0, sid, seq)

        crypted = aes.crypt(pt_data)

        ct = struct.unpack('!4L', crypted)
        pt = struct.unpack('<4L', data[pos:pos+16])

        ret.extend([
                ct[x] ^ pt[x]
                for x in [0,1,2,3]
        ])
        seq += 1
        pos += 16

    str_ret = struct.pack('<%dL' % len(ret), *ret)

    if sz > pos:
        pt_data = struct.pack('<4L', sid, 0, sid, seq)
        crypted = aes.crypt(pt_data)
        ct = struct.unpack('!16B', crypted)
        pt = struct.unpack('<%dB' % (sz-pos), data[pos:])
        ret =[
            ct[x^3] ^ pt[x]
            for x in range(sz - pos)
        ]
        str_ret += struct.pack('<%dB' % len(ret), *ret)

    return str_ret
