from math import pow
import struct
from lib.challenge2 import random_nbytes
from lib.challenge33 import modexp
from random import randint

p = 23
g = 5

print "Practice"
#ra = struct.unpack('>I',random_nbytes(4))[0]
ra = randint(0,20000)
a =   ra % p
A = modexp(g,a,p)
#A = ( pow(g,a) ) % p

#rb = struct.unpack('>I',random_nbytes(4))[0]
rb = randint(0,20000)
b = rb % p
B = modexp(g,b,p)
#B = ( pow(g,b) ) % p

print 'a: {a} A: {A}'.format(a=a,A=A)
print 'b: {b} B: {B}'.format(b=b,B=B)

sa = pow(B,a) % p
sb = pow(A,b) % p

print 'sa: {sa}\tsb: {sb}'.format(sa=sa,sb=sb)
assert(sa == sb)

p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

g = 2

print "Real"
#ra = struct.unpack('>I',random_nbytes(4))[0]
ra = randint(0,20000)
a =   ra % p
A = modexp(g,a,p)

#rb = struct.unpack('>I',random_nbytes(4))[0]
rb = randint(0,20000)
b = rb % p
B = modexp(g,b,p)

print 'a: {a} A: {A}'.format(a=a,A=A)
print 'b: {b} B: {B}'.format(b=b,B=B)

sa = modexp(B,a,p)
sb = modexp(A,b,p)
print 'sa: {sa}\tsb: {sb}'.format(sa=sa,sb=sb)
assert(sa == sb)
