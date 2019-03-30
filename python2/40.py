from lib.challenge39 import generate_rsa_keypairs, simple_rsa
from lib.challenge40 import crt, cube_root
import random

msg = random.randint(30,150)
print "original message: {d}".format(d=msg)

kp1 = generate_rsa_keypairs( (100,200), e = 3)
print "keypair 1: {kp}".format(kp = kp1)
pub1, priv1 = kp1
cm1 = simple_rsa(msg,pub1)
print "encrypted msg 1: {cm}".format(cm = cm1)
cn1 = (cm1, pub1[1])

kp2 = generate_rsa_keypairs( (300,400), e = 3)
print "keypair 2: {kp}".format(kp = kp2)
pub2, priv2  = kp2
cm2 = simple_rsa(msg,pub2)
print "encrypted msg 2: {cm}".format(cm = cm2)
cn2 = (cm2, pub2[1])

kp3 = generate_rsa_keypairs( (400,500), e = 3)
print "keypair 3: {kp}".format(kp = kp3)
pub3, priv3  = kp3
cm3 = simple_rsa(msg,pub3)
print "encrypted msg 3: {cm}".format(cm = cm3)

cn3 = (cm3, pub3[1])

r,n = crt(cn1,cn2,cn3)
cr = cube_root(r)
print "crt decrypt msg: {cr}".format(cr=cr)
assert(cr == msg)
