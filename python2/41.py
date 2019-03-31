import random
import binascii

from lib.challenge39 import generate_rsa_keypairs,simple_rsa, inverse_modulo
from lib.challenge41 import int2str

p_range = ( pow(2,45), pow(2,50) )
server_kp = generate_rsa_keypairs(p_range, e=3)
server_pub, server_priv = server_kp

print "pub: {p}".format(p=server_pub)
print "priv: {p}".format(p=server_priv)
msg = "{secret}"
print 'msg: {m}'.format(m=msg)
imsg =  int(binascii.hexlify(msg),16)
cmsg = simple_rsa( imsg, server_pub)
print 'encrypt: {c}'.format(c=cmsg)

# simple sanity check
# some text get large enough that pow isn't happy
sanity = simple_rsa( cmsg, server_priv )
assert(sanity == imsg)
assert(int2str(sanity) == msg )

e,n = server_pub
s = random.randint( 2, n-1 )

print "s  = {s}".format(s=s)
c_atk = (pow(s,e,n) * cmsg) % n
print "c' = {c}".format(c=c_atk)
p_atk = simple_rsa( c_atk, server_priv )
print "p' = {p}".format(p=p_atk)

z = (p_atk * inverse_modulo(s,n)) % n
print 'atk: {a}'.format(a=repr(int2str(z)))
assert(z == imsg)
