from lib.challenge28 import secret_mac
from lib.challenge2 import random_nstr

msg = random_nstr(100)
print "msg: ",repr(msg)

hmac = secret_mac(msg)

print "hmac: ",repr(hmac)

print "mod: ",repr(secret_mac(msg[:-1]))
