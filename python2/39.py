from lib.challenge39 import simple_rsa, generate_rsa_keypairs
from lib.challenge33 import modexp

prange = [2000,3000]
pub_key, priv_key = generate_rsa_keypairs(prange)

print "pub: {p}".format(p=pub_key)
print "priv: {p}".format(p=priv_key)

test = 42
print "\ntest: {t}".format(t=test)
etest = simple_rsa(test,pub_key)
print "encrypted test: {t}".format(t=etest)
sanity = simple_rsa(etest,priv_key)
print "decrypted test: {t}\n".format(t=sanity)
assert(sanity == test)

import binascii
test = int(binascii.hexlify("hi"),16)
print "test: {t}".format(t=test)
etest = simple_rsa(test,pub_key)
print "encrypted test: {t}".format(t=etest)
sanity = simple_rsa(etest,priv_key)
print "decrypted test: {t}".format(t=sanity)
assert(sanity == test)
