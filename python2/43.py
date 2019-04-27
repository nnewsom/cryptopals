import binascii
import hashlib
import struct

from lib.challenge41 import (
        int2str,
    )
from lib.challenge43 import (
        dsa_sign,
        dsa_sign_insecure,
        dsa_verify,
        gen_dsa_params,
        gen_user_keys,
        nonce_recover_key
    )

## I just couldn't get this to work despite having my algs run fine. 
## Not able to even verify the given signature with the given values

## tested against random generated values instead of sequential
## tested agianst externally generated parms, was able to verify 3rd party signatures fine
## the two new-lines in the message is pretty misleading. makes me question everything else is being
## read correctly and thats why i am not able to even verify the signature with the given params

## every challenge until now has been very clear on given info
## I figure this is just gen dsa + brutefocing the weak k selection
## so I'll just prove that and move on

#  msg = """For those that envy a MC it can be hazardous to your health
#  So be friendly, a matter of life and death, just like a etch-a-sketch
#  """
#  assert( int(hashlib.sha1(msg).hexdigest(),16) == 0xd2d0714f014a9784047eaeccf956520045c45265)
#  
#  p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
#   
#  q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
#  
#  g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
#  
#  y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17
#  
#  r = 0x548099063082341131477253921760299949438196259240
#  s = 0x857042759984254168557880549501802188789837994940
#  
#  pubkey = ( p,q,g,y )
#  
#  # this fails... so are my algs even correct?
#  # Yup. verified my algs work with externally generated parmas in lib function sanity_check_algs()
#  # ...pretty frustrating and confusng
#  # assert( dsa_verify(pubkey,(r,s),msg) == True )
#  
#  for k in xrange(1,pow(2,16)):
#      x = nonce_recover_key(msg,r,s,q,k)
#      # the sha1 digest of the number...as raw bytes? or as str(int)
#      # vague/confusing with python api. guess ill check both
#      if hashlib.sha1(int2str(x)).hexdigest() == "0954edd5e0afe5542a4adf012611a91912a3ec16":
#          raw_input("found")
#      if hashlib.sha1(str(x)).hexdigest() == "0954edd5e0afe5542a4adf012611a91912a3ec16":
#          raw_input("found")
#      prvkey = ( p,q,g,x)
#      xr,xs,xk = dsa_sign(prvkey,msg,k=k)
#      if xr == r and xs == s:
#          raw_input("found")
#          break

p,q,g = gen_dsa_params()
kpub,kpriv = gen_user_keys(p,q,g)
msg = "A very clear and simple sentence for a challenge. notice no newlines hidden at the end?"
r,s,_k = dsa_sign_insecure( kpriv, msg)
v = dsa_verify( kpub, (r,s), msg)
assert(v == True)
x = 0
print "bruteforcing weak k"
for k in xrange(1,pow(2,16)):
    x = nonce_recover_key(msg,r,s,q,k)
    xpriv = (p,q,g,x)
    xr,xs,xk = dsa_sign(xpriv,msg,k=k)
    if xr == r and xs == s:
        break

print "private key: {}".format(hex(x))
assert(x == kpriv[-1])
