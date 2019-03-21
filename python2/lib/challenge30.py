import struct
from challenge2 import random_nstr

SECRET_KEY = random_nstr(15)

def secret_md4_mac(msg):
    m = MD4()
    m.update(SECRET_KEY + msg)
    return m.hexdigest()

def generate_md4_padding(msg):
    byte_length = len(msg)
    padding = ''
    padding += '\x80'
    padding += '\x00' * ( (55 - byte_length) % 64)
    bit_length = byte_length * 8
    padding += struct.pack('<Q',bit_length)
    return padding

def leftrotate(i, n):
    return ((i << n) & 0xffffffff) | (i >> (32 - n))

def F(x,y,z):
    return (x & y) | (~x & z)

def G(x,y,z):
    return (x & y) | (x & z) | (y & z)

def H(x,y,z):
    return x ^ y ^ z

class MD4(object):
    def __init__(self, data=""):
        self.remainder = data
        self.count = 0
        self.glue = ""
        self.h = [
                0x67452301,
                0xefcdab89,
                0x98badcfe,
                0x10325476
                ]

    def _add_chunk(self, chunk):
        self.count += 1
        X = list( struct.unpack("<16I", chunk) + (None,) * (80-16) )
        h = [x for x in self.h]
        # Round 1
        s = (3,7,11,19)
        for r in xrange(16):
            i = (16-r)%4
            k = r
            h[i] = leftrotate( (h[i] + F(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k]) % 2**32, s[r%4] )
        # Round 2
        s = (3,5,9,13)
        for r in xrange(16):
            i = (16-r)%4 
            k = 4*(r%4) + r//4
            h[i] = leftrotate( (h[i] + G(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k] + 0x5a827999) % 2**32, s[r%4] )
        # Round 3
        s = (3,9,11,15)
        k = (0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15) #wish I could function
        for r in xrange(16):
            i = (16-r)%4 
            h[i] = leftrotate( (h[i] + H(h[(i+1)%4], h[(i+2)%4], h[(i+3)%4]) + X[k[r]] + 0x6ed9eba1) % 2**32, s[r%4] )

        for i,v in enumerate(h):
            self.h[i] = (v + self.h[i]) % 2**32

    def update(self, data):
        message = self.remainder + data
        r = len(message) % 64
        if r != 0:
            self.remainder = message[-r:]
        else:
            self.remainder = ""
        for chunk in xrange(0, len(message)-r, 64):
            self._add_chunk( message[chunk:chunk+64] )
        return self

    def digest(self):
        l = len(self.remainder) + 64 * self.count
        self.glue = "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8) 
        self.update( "\x80" + "\x00" * ((55 - l) % 64) + struct.pack("<Q", l * 8) )
        out = struct.pack("<4I", *self.h)
        return out

    def hexdigest(self):
        return self.digest().encode('hex')
