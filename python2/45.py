import hashlib
import itertools
import random

from lib.challenge39 import (
        inverse_modulo
    )

from lib.challenge43 import (
        dsa_sign,
        dsa_verify,
        gen_dsa_params,
        gen_user_keys,
    )

p,q,g = gen_dsa_params()
hello = "Hello, world"
bye = "Goodbye, world"

## 0 mod p generators will not work on my impl of dsa_sign
## since I followed the wiki alg and continue to gen r
## while it's 0. 0 to any power will always be 0, 
## so endless loop

# #generators that are 0 mod p
# print "0 mod p generator"
# 
# pub,priv = gen_user_keys(p,q,0)
# r,s,k = dsa_sign(priv,hello)
# v = dsa_verify(priv,(r,s),hello)
# print "'{m}' sig: ({r},{s}), verify: {v} ".format(m=hello,r=hex(r),s=hex(s),v=v)
# v = dsa_verify(priv,(r,s),bye)
# print "'{m}' sig: ({r},{s}), verify: {v} ".format(m=bye,r=hex(r),s=hex(s),v=v)

#generators that are 1 mod p
print "1 mod p generator"
pub,priv = gen_user_keys(p,q,p+1)
r,s,k = dsa_sign(priv,hello)
v = dsa_verify(pub,(r,s),hello)
print "'{m}' sig: ({r},{s}), verify: {v} ".format(m=hello,r=hex(r),s=hex(s),v=v)
v = dsa_verify(pub,(r,s),bye)
print "'{m}' sig: ({r},{s}), verify: {v} ".format(m=bye,r=hex(r),s=hex(s),v=v)
