import itertools
import base64
import string
from itertools import combinations
from challenge3 import break_xor_byte

def str2bin(s):
    return ''.join ( [ '{0:08b}'.format(ord(c)) for c in s] )

def hamming_distance(s1, s2):
    assert len(s1) == len(s2)
    s1 = str2bin(s1)
    s2 = str2bin(s2)
    count = 0
    for c1,c2 in zip(s1, s2):
        if ord(c1) ^ ord(c2) == 1:
            count +=1

    return sum( ord(c1) ^ ord(c2) for c1, c2 in zip(s1, s2))

def normalize_hamming_distance(msg):
    distances = {}
    for kl in xrange(1,43):
        try:
            b1 = msg[0:kl]
            b2 = msg[kl:kl*2]
            b3 = msg[kl*2:kl*3]
            b4 = msg[kl*3:kl*4]
            d = 0
            for _b1,_b2 in combinations([b1,b2,b3,b4],2):
                _d = hamming_distance(_b1,_b2)
                d += float(_d) / float(kl)

            distances[kl] = float(d) / float(4)
        except AssertionError:
            pass # blocks are not equal

    min_distance = min(distances.values())
    for kl,d in distances.iteritems():
        if d == min_distance:
            return kl

def break_xor_repeating(msg,kl):
    blocks = [ msg[i:i+kl] for i in xrange(0,len(msg),kl) ]
    transposed_blocks = list( itertools.izip_longest(*blocks,fillvalue='0') )
    key = [ break_xor_byte(block)[0] for block in transposed_blocks]
    key = "".join([ chr(c) for c in key])
    return key

