import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def get_MSB(value, nbit):
    if nbit < 0:
        return 0
    return (value >> (31 - nbit)) & 1

def set_MSB(result, nbit, bit):
    return result | (bit << (31 - nbit))

def unshift_xor_right(value,shift):
    r = 0
    for nbit in xrange(32):
        r = set_MSB(
            result = r, 
            nbit = nbit,
            bit = get_MSB(value, nbit) ^ get_MSB(r, nbit - shift)
        )
    return r

def get_LSB(value, nbit):
    if nbit < 0:
        return 0
    return (value >> nbit) & 1

def set_LSB(result, nbit, bit):
    return result | (bit << nbit)

def unshift_xor_left_mask(value, shift, mask):
    r = 0
    for nbit in xrange(32):
       r = set_LSB(
            result = r, 
            nbit = nbit, 
            bit = get_LSB(value, nbit) ^ (get_LSB(r, nbit - shift) & get_LSB(mask, nbit))
        )
    return r

def reverse_mersenne(value):
    value = unshift_xor_right(value,18)
    value = unshift_xor_left_mask(value,0xf,0xefc60000)
    value = unshift_xor_left_mask(value,0x7,0x9d2c5680)
    value = unshift_xor_right(value,0xb)
    return value
