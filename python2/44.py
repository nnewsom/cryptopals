import hashlib
import random
import itertools

from lib.challenge39 import (
        inverse_modulo
    )

from lib.challenge43 import (
        dsa_sign,
        dsa_sign_insecure,
        dsa_verify,
        gen_dsa_params,
        gen_user_keys,
        nonce_recover_key
    )

## suprise! these also also cannot be verified. so i'll recreate the challenge and solve it
## whatever the author did different, it's consistent across teh challenges
## will probably see it next challenge too :(

# p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
#  
# q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
# 
# g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291
# 
# y = 0x2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821
# 
# pubkey = ( p,q,g,y )
# 
# data = open('./data/44.txt').read().split('\n')
# 
# grps = [ data[i:i+4] for i in xrange(0,len(data),4)]
# for g in grps:
#     msg,s,r,m = map(lambda x: x.split(':')[-1].lstrip(), g) # need to preserve spaces at end
#     print repr(msg)
#     print s,r
#     print m
#     assert( hashlib.sha1(msg).hexdigest() == m )
#     assert( dsa_verify( pubkey, (r,s), msg) == True )


# challenge setup
class Block(object):
    def __init__(self,msg,r,s,m):
        self.msg = msg
        self.r = r
        self.s = s
        self.m = m

def valid_keypair(priv,pub):
    msg =  "TESTINGKEYPAIRS"
    r,s,jk = dsa_sign(priv,msg)
    v = dsa_verify( pub ,(r,s),msg)
    return v
    
msgs = [
    "sRROAg6Irx8wjCcUfpmZhMIG2Jk3 hzYycsx31E3dU9oZBFnMKMofPAq4Zbg8VIQkQNL329S zz",
    "DNBPE2nk4XX4V893PwgQeKVkKGi6ZaJeAhaO3XYsN7UxSNSsNSmeMKZnak4EM1TVgksskBfyL386O",
    "9vkatbP7KV7h62CGzIygwRF2i8ycRRkrpbZAaEmOIqkv16BZOUxAwoYOjYO dxZG5mi2Gb",
    "ABJoZ3nM8NpqkBnl4CLBgfUKZdhyTwPJ5SvAH AwNFGljpQ090PAUhUyvi8HtJcLMTdpcCN70pB5NV",
    "ULZGb94klBjMNFJGZsKsvc TRrxghHJ7nd9bPMFTdzvd8T GAue7Ph2giyxc1raZm10svIyMfp",
    "KYOzDLtxxlS ikzsvtEhyM7E4 A4GIg9lxnA aseUTDhWxree9X3BHVNl3CdmkUBU7Vhz",
    "e7hVvG3UpG7fpWlq2twalD8KFosWtcTmYogVGDTdYXXeyoCM4 bDpgLsbFSJk",
    "ME2TiIqg 4BwskWHJCfHZ jlve8zeAmcCktDNihIbhPMXIBCxLe9YWRldCGGciL430vfe9",
    "ENuZxAFtCsxOqax7hMKt4jl30TxMvc54QQ8MbkG7 Udih2Sr7GIfRAYr72NfVuIiqSBrU3cA8hl7cN8",
    "xE7dEMf6TQr CB4WuQR9rvNzqZzUok7umxlCKv6okMcxc6rqjAElF0Y4DynoY3374cY2OQwLPfZFl3Z",
    "Oi4r6MQseSAI7VAfzbKiK7JxHnCcwJV cTst8uORORSaIExp4z20N5 uazujUYpBO2CR9vZR9N",
]

sharedk = 0
sharedk_msgs = [ random.choice(msgs) for _ in xrange(random.randint(3,len(msgs))) ]
print "There are {} blocks sharing a nonce".format(len(sharedk_msgs))

p,q,g = gen_dsa_params()
pub,priv = gen_user_keys(p,q,g)
print "priv key used: {}".format(priv[-1])

blks = []
for msg in msgs:
    if msg in sharedk_msgs:
        if not sharedk:
            r,s,sharedk = dsa_sign( priv, msg )
        else:
            r,s, junk = dsa_sign(priv, msg, fixedk=sharedk )
    else:
        r,s,junk = dsa_sign( priv, msg )

    m =  int(hashlib.sha1(msg).hexdigest(),16) 
    b = Block(  
            msg =msg,
            r = r,
            s = s,
            m = m
        )
    blks.append( b ) 

for blk in blks:
    assert( dsa_verify( pub, (blk.r,blk.s), blk.msg) == True)

# end setup

# x gonna give it to ya
x_gen = {}
# challenge solve
for blk_grp in itertools.combinations(blks,2):
    blk_a, blk_b = blk_grp
    # ( (m1 - m2) / (s1 - s2) ) mod q
    pm = blk_a.m - blk_b.m
    ps = inverse_modulo( blk_a.s - blk_b.s, q )
    k = (pm * ps) % q
    if k not in x_gen:
        x_gen[k] = []
    x_gen[k].append( (blk_a,blk_b) )

count = 0
max_k = 0
for k,v in x_gen.iteritems():
    if len(v) > count:
        count = len(v)
        max_k = k

blocks = x_gen[max_k]
found_keys = []
for b,a in blocks:
    x = nonce_recover_key( b.msg, b.r, b.s, q, max_k )
    xpriv = (p,q,g,x)
    if valid_keypair(xpriv,pub):
        found_keys.append( x )

for key in found_keys:
    assert(priv[-1] == key )
print "key recovered: {}".format(found_keys[0])
