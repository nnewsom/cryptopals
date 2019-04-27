import hashlib
import logging
import random

from challenge33 import modexp
from challenge39 import (
        is_prime,
        gen_seq_prime,
        inverse_modulo
    )
from challenge41 import (
        str2int16,
        int2str
    )

# openssl dsaparam -outform PEM -genkey 1024
# openssl dsa -in dsa_parmas.pem -text
# and my dgst doesn't have -dss1 sooo online calcuator it is

# https://8gwifi.org/dsafunctions.jsp
# openssl dsa -in dsa.priv -text
# read DSA key
# Private-Key: (1024 bit)
# priv:
#     00:88:07:21:f1:85:a1:5e:51:61:ec:2b:3e:9a:95:
#     d7:78:e0:0f:e0:64
# pub: 
#     6c:34:b8:a2:e1:86:42:de:28:48:1e:2f:1f:0c:aa:
#     52:c3:a0:9d:14:ef:64:5c:cc:bf:38:f0:f8:9a:7f:
#     20:78:8e:2b:6f:ee:1d:55:e9:a4:ff:0f:02:a7:bf:
#     1d:98:ba:e7:0f:eb:83:f6:6d:28:6f:52:39:bf:4f:
#     bd:bd:32:6a:5f:9e:de:c5:e4:0e:44:5b:d8:b3:f4:
#     5b:9c:50:f8:e2:be:48:8b:5d:94:f5:c9:34:18:10:
#     19:74:a4:d4:f4:b2:38:b8:9c:98:96:79:03:85:62:
#     e9:a7:fe:a5:79:64:ff:6d:e4:fc:fd:a2:6c:60:01:
#     12:55:0d:c8:0b:37:15:2a
# P:   
#     00:ad:e9:41:e2:d9:c8:42:ad:fd:0f:47:8e:fd:96:
#     10:31:ef:e7:08:42:32:df:5b:bb:fb:84:63:df:f3:
#     43:5c:6f:79:89:25:33:33:99:8a:3b:09:1a:54:7f:
#     34:76:e3:2e:fd:63:c7:d5:7e:36:5c:e9:c9:b2:02:
#     3b:53:57:d8:cc:68:27:4c:2b:81:fa:3c:0b:a0:2b:
#     3a:85:34:9c:27:77:08:86:b2:eb:ee:16:d1:8a:39:
#     07:81:6b:94:42:c9:43:45:51:25:1e:37:11:ed:7b:
#     12:f2:f6:1e:a9:b9:58:bb:7a:c3:f7:6f:30:01:7c:
#     72:a9:62:38:6e:a7:3a:a1:75
# Q:   
#     00:8e:da:8e:14:64:1e:f0:a4:b2:ba:b4:98:69:91:
#     9d:e0:0e:39:59:e1
# G:   
#     5f:1d:d9:d4:08:c2:c0:6c:16:11:86:eb:94:17:4a:
#     df:84:f2:1a:1d:61:bc:73:b9:ac:e0:b1:02:d8:5b:
#     ac:9c:67:4a:bf:ad:f6:04:78:89:1f:af:95:62:1e:
#     0e:4f:66:47:c8:4d:c3:42:14:de:83:ec:7e:42:49:
#     17:a7:d7:08:21:b4:0b:70:78:d3:22:c4:35:05:3f:
#     c7:26:8f:28:db:30:21:71:64:92:3d:15:5a:0a:89:
#     9b:50:96:a1:d8:11:2a:28:10:c8:bd:d9:7a:3f:4c:
#     15:48:5e:5a:ae:e1:8c:b0:d2:e1:89:ef:b2:ac:b8:
#     2c:85:97:9f:ee:60:75:1c

# $ xxd test.sig 
# 00000000: 302c 0214 593e 749c 26c4 38bd c4ce d12c  0,..Y>t.&.8....,
# 00000010: 68bb 2824 8a45 64bb 0214 0d64 eb8f 237f  h.($.Ed....d..#.
# 00000020: 4641 867b 20ff 7d93 ff73 349c 37a7       FA.{ .}..s4.7.

# $ xxd test
# 00000000: 5341 4e49 5459 5445 5354 0a              SANITYTEST.


SHA1_BIT_LENGTH = 160 
DSA_MAX_L = 3072

def gen_dsa_params():
    # FIPS L,N (1024,160), (2048,224), (2048,256), (3072,256)
    # choose L, multiple of 64 between 512-1024, 2048, 3072
    l = 1024
    # n must be less than or equal to length of hash
    n = SHA1_BIT_LENGTH
    # choose n bit prime q
    q = gen_seq_prime(start = pow(2,n) + pow(2,random.randint(8,16)))
    # choose l bit prime p such that p-1 is multiple of q

    i = pow(2,l) + pow(2,random.randint(8,16))
    while True:
        p = q * i 
        if is_prime(p+1):
            break
        i +=1
    p+=1
    assert(is_prime(p))
    assert((p-1) % q == 0)

    # chose smallest int g such that g^q = 1 mod p
    h = 1
    x = (p-1)/q
    while h < p-1:
        g = modexp(h,x,p)
        h +=1
        if g == 1:
            continue
        elif modexp(g,q,p) != 1:
            continue
        else:
            break

    return (p,q,g)

def gen_user_keys(p,q,g):
    x = random.randint(0,q) 
    y = modexp(g,x,p)
    priv_key = (p,q,g,x)
    pub_key = (p,q,g,y)
    return [ pub_key, priv_key ]

def dsa_sign_insecure(pkey,msg):
    p,q,g,key = pkey

    r = 0
    k = 0
    s = 0
    while s == 0:
        while r == 0: 
            k = random.randint(1,pow(2,16))
            r = modexp(g,k,p) % q

        h = hashlib.sha1(msg).digest()
        h = str2int16(h)
        np1 = inverse_modulo(k,q)
        np2 = ( h + r * key ) % q
        s = ( np1 * np2 )  %  q

    return (r,s,k)

def dsa_sign(pkey,msg,fixedk=0):
    p,q,g,key = pkey

    r = 0
    k = 0
    s = 0
    while s == 0:
        if fixedk:
            k = fixedk
            r = modexp(g,fixedk,p) % q
        else:
            while r == 0: 
                k = random.randint(1,q)
                r = modexp(g,k,p) % q

        h = hashlib.sha1(msg).digest()
        h = str2int16(h)
        np1 = inverse_modulo(k,q)
        np2 = ( h + r * key ) % q
        s = ( np1 * np2 )  %  q

    return (r,s,k)

def dsa_verify(pkey,sig,msg):
    p,q,g,key = pkey
    r,s = sig
    if r < 0 or r > q:
        return False
    if s < 0 or s > q:
        return False
    w = inverse_modulo(s,q)
    h = int( hashlib.sha1(msg).hexdigest(),16 )
    u1 = (h * w) % q
    u2 = (r * w) % q

    # (A*B) Mod C == (A Mod C * B Mod C ) Mod C
    part1 = modexp(g,u1,p)
    part2 = modexp(key,u2,p)
    v = (( part1 * part2 ) % p ) % q
    logging.debug("v: {}".format(v))
    logging.debug("r: {}".format(r))
    return v == r

def nonce_recover_key(msg,r,s,q,k):
    t = ( s * k ) - int( hashlib.sha1(msg).hexdigest(),16 )
    ir = inverse_modulo(r,q)
    x = (t * ir) % q
    return x

def test_gen_verify():
    p,q,g = gen_dsa_params()
    logging.debug("p: {}".format(p))
    logging.debug("q: {}".format(q))
    logging.debug("g: {}".format(g)) 
    kpub,kpriv = gen_user_keys(p,q,g)
    logging.debug("kpub: {}".format(kpub))
    logging.debug("kpriv: {}".format(kpriv))

    msg = "footestfoo"
    r,s,k = dsa_sign( kpriv, msg)
    logging.debug("msg: {}".format(msg))
    logging.debug("r: {}".format(r))
    logging.debug("s: {}".format(s))
    # test success
    v = dsa_verify( kpub, (r,s), msg)
    logging.debug('verify: {}'.format(v))
    assert(v == True)
    # test fail
    v = dsa_verify( kpub, (r,s+1), msg)
    logging.debug('verify: {}'.format(v))
    assert( v == False)

def test_recover_key():
    p,q,g = gen_dsa_params()
    kpub,kpriv = gen_user_keys(p,q,g)
    
    msg = "footestfoo"
    r,s,k = dsa_sign( kpriv, msg)
    x = nonce_recover_key(msg,r,s,q,k)
    logging.debug('derived: {}'.format(hex(x)))
    logging.debug('expected: {}'.format(hex(kpriv[-1])))
    assert(x == kpriv[-1] )

def sanity_check_algs():
    test_external_params()
    test_cryptography_module()

def test_external_params():
    # Private-Key: (1024 bit)
    # priv:
    x = "0x"
    x+= "00:88:07:21:f1:85:a1:5e:51:61:ec:2b:3e:9a:95:"
    x+= "d7:78:e0:0f:e0:64"
    x = int(x.replace(':',''),16)

    # pub: 
    y = "0x"
    y+= "6c:34:b8:a2:e1:86:42:de:28:48:1e:2f:1f:0c:aa:"
    y+= "52:c3:a0:9d:14:ef:64:5c:cc:bf:38:f0:f8:9a:7f:"
    y+= "20:78:8e:2b:6f:ee:1d:55:e9:a4:ff:0f:02:a7:bf:"
    y+= "1d:98:ba:e7:0f:eb:83:f6:6d:28:6f:52:39:bf:4f:"
    y+= "bd:bd:32:6a:5f:9e:de:c5:e4:0e:44:5b:d8:b3:f4:"
    y+= "5b:9c:50:f8:e2:be:48:8b:5d:94:f5:c9:34:18:10:"
    y+= "19:74:a4:d4:f4:b2:38:b8:9c:98:96:79:03:85:62:"
    y+= "e9:a7:fe:a5:79:64:ff:6d:e4:fc:fd:a2:6c:60:01:"
    y+= "12:55:0d:c8:0b:37:15:2a"
    y = int(y.replace(':',''),16)

    # P:   
    p = "0x"
    p += "00:ad:e9:41:e2:d9:c8:42:ad:fd:0f:47:8e:fd:96:"
    p += "10:31:ef:e7:08:42:32:df:5b:bb:fb:84:63:df:f3:"
    p += "43:5c:6f:79:89:25:33:33:99:8a:3b:09:1a:54:7f:"
    p += "34:76:e3:2e:fd:63:c7:d5:7e:36:5c:e9:c9:b2:02:"
    p += "3b:53:57:d8:cc:68:27:4c:2b:81:fa:3c:0b:a0:2b:"
    p += "3a:85:34:9c:27:77:08:86:b2:eb:ee:16:d1:8a:39:"
    p += "07:81:6b:94:42:c9:43:45:51:25:1e:37:11:ed:7b:"
    p += "12:f2:f6:1e:a9:b9:58:bb:7a:c3:f7:6f:30:01:7c:"
    p += "72:a9:62:38:6e:a7:3a:a1:75"
    p = int(p.replace(':',''),16)

    # Q:   
    q = "0x"
    q += "00:8e:da:8e:14:64:1e:f0:a4:b2:ba:b4:98:69:91:"
    q += "9d:e0:0e:39:59:e1"
    q = int(q.replace(':',''),16)

    # G:   
    g = "0x"
    g += "5f:1d:d9:d4:08:c2:c0:6c:16:11:86:eb:94:17:4a:"
    g += "df:84:f2:1a:1d:61:bc:73:b9:ac:e0:b1:02:d8:5b:"
    g += "ac:9c:67:4a:bf:ad:f6:04:78:89:1f:af:95:62:1e:"
    g += "0e:4f:66:47:c8:4d:c3:42:14:de:83:ec:7e:42:49:"
    g += "17:a7:d7:08:21:b4:0b:70:78:d3:22:c4:35:05:3f:"
    g += "c7:26:8f:28:db:30:21:71:64:92:3d:15:5a:0a:89:"
    g += "9b:50:96:a1:d8:11:2a:28:10:c8:bd:d9:7a:3f:4c:"
    g += "15:48:5e:5a:ae:e1:8c:b0:d2:e1:89:ef:b2:ac:b8:"
    g += "2c:85:97:9f:ee:60:75:1c"
    g = int(g.replace(':',''),16)

# $ xxd sanity.sig 
# 00000000: 302c 0214 593e 749c 26c4 38bd c4ce d12c  0,..Y>t.&.8....,
# 00000010: 68bb 2824 8a45 64bb 0214 0d64 eb8f 237f  h.($.Ed....d..#.
# 00000020: 4641 867b 20ff 7d93 ff73 349c 37a7       FA.{ .}..s4.7.

# RFC 3279 2.2.2
# openssl asn1parse -inform DER -in sanity.sig 
#     0:d=0  hl=2 l=  44 cons: SEQUENCE          
#     2:d=1  hl=2 l=  20 prim: INTEGER           :593E749C26C438BDC4CED12C68BB28248A4564BB
#    24:d=1  hl=2 l=  20 prim: INTEGER           :0D64EB8F237F4641867B20FF7D93FF73349C37A7

    r = 0x593E749C26C438BDC4CED12C68BB28248A4564BB
    s = 0x0D64EB8F237F4641867B20FF7D93FF73349C37A7
    
    msg = 'SANITYTEST\x0a'
    priv = (p,q,g,x)
    pub = (p,q,g,y)
    
    logging.debug("sanity checking verify with externally generated params+keys")
    assert( dsa_verify(pub,(r,s),msg) == True )

def test_cryptography_module():
    try:
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa
        from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

        privk = dsa.generate_private_key(
                    key_size = 1024,
                    backend = default_backend()
            )

        params = privk.parameters().parameter_numbers()
        p,q,g = params.p,params.q,params.g

        pubk = privk.public_key()
        y = pubk.public_numbers().y

        data = "SANITY_TESTSANITY_TEST_SANITYTEST"

        sig = privk.sign( data, hashes.SHA1() )
        r,s = decode_dss_signature(sig)

        pub = (p,q,g,y)

        logging.debug("sanity checking verify with cryptography module generated params+keys")
        assert(dsa_verify(pub,(r,s),data) == True)

    except ImportError:
        logging.error("cannot test using another source (cryptography module)")


if __name__ == "__main__":
    logging.basicConfig(
            format="[%(asctime)s][%(levelname)s][%(funcName)s:%(lineno)d] %(msg)s",
            level=logging.DEBUG
            )

    test_gen_verify()
    test_recover_key()
    sanity_check_algs()
