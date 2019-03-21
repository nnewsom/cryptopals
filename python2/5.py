from lib.challenge5 import repeat_xor_str,repeat_xor_ints
import sys

print 'TEST 1'

t1 = "Burning 'em, if you ain't quick and nimble"
e1 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"

int_t1 = [ ord(c) for c in t1]
int_r1 = repeat_xor_ints("ICE",int_t1)
hex_r1 =  "".join([ "%0.2X" % i for i in int_r1 ])
print hex_r1

hex_r1 = repeat_xor_str('ICE',t1)
print hex_r1
