import struct
import binascii
import logging
import hashlib

from challenge39 import simple_rsa
from challenge40 import cube_root
from challenge41 import str2int16,int2str

# https://tools.ietf.org/html/rfc2313 PKCS 1.5
# 10.1 signature process
# 4 steps
# * message digest
# * data encode
# * rsa encryption
# * octect-string-to-bit-string conversion

# message digest
# digest alg into MD
# DigestInfo :: = SEQUENCE {
#  digestAlgorithm DigestAlgorithmIdentifier,
#  digest Digest
# }
# DigestAlgorithmIdentifer ::= AlgorithmIdentifier
# digest ::= OCTET STRING
#

# Data encode
# MD + alg stored in ASN.1 type DigestInfo BER encoded

# https://tls.ulfheim.net/certificate.html

# Signature Algorithm
# 30 0d 06 09 2a 86 48 86 f7 0d 01 01 0b 05 00
# 30 - constructed universal type sequence
# 0d - sequence length of 0xD (13) bytes
# 06 - universal type object ID (OID)
# 09 - OID length of 0x9 (9) bytes
# 2a 86 48 86 f7 0d 01 01 0b - OID 1.2.840.113549.1.1.11 "Sha256WithRSAEncryption"
# 05 - universal type null (params)
# 00 - null length 0x0 (0) bytes

# md5 rsa 1.2.840.113549.1.1.4
# md4 rsa 1.2.840.113549.1.1.2

# Signature
# 03 82 01 01 00 59 16
# 03 - universal type bitstring
# 82 01 01 - long-form bitstring length 0x101 (257) bytes
# 00 - right-padded by 0x0 (0) bits
# 59 16 .. 36 a0 - signature

##  $ xxd verifyme
##  00000000: 5445 5354 4d45 0a                        TESTME.
##
##  $ openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:1024
##
##  $ openssl rsa -pubout -in private_key.pem -out public_key.pem
##
##  $ openssl rsautl -sign -inkey private_key.pem -keyform PEM -in verifyme > verifyme.rsautil
##
##  $ openssl rsautl -verify -in verifyme.rsautil  -inkey private_key.pem -raw -hexdump
##  0000 - 00 01 ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
##  0010 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
##  0020 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
##  0030 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
##  0040 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
##  0050 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
##  0060 - ff ff ff ff ff ff ff ff-ff ff ff ff ff ff ff ff   ................
##  0070 - ff ff ff ff ff ff ff ff-00 54 45 53 54 4d 45 0a   .........TESTME.

# ltrace openssl rsautl -verify -in verifyme.rsautil  -inkey private_key.pem (excerts)
##  RAND_load_file(0x7ffeb6998fc0, -1, 0x7f2514187e76, 22)          = 1024
##  PEM_read_bio_PrivateKey(0x55ba06ac5790, 0, 0x55ba04cd3ca0, 0x7ffeb6999070) = 0x55ba06ad4c90
##  EVP_PKEY_get1_RSA(0x55ba06ad4c90, 0, 0, 1)                      = 0x55ba06ad3530
##  RSA_size(0x55ba06ad3530, 106, 1, 0)                             = 128
##  RSA_public_decrypt(128, 0x55ba06ad5bd0, 0x55ba06ad2750, 0x55ba06ad3530) = 7

# https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE

ASN_UNIVERSAL_OID = 0x06
ASN_UNIVERSAL_SEQ = 0x30
ASN1_UTYPE_SEQ = 0x30
ASN1_UTYPE_OID = 0x06
ASN1_UTYPE_NULL = 0x05
ASN1_UTYPE_BITSTRING =0x03

OID_RSA_MD5_STR = "1.2.840.113549.1.1.4"
OID_RSA_INT = 113549
OID_RSA_MD5_INT = 4

def binstr(i,size=8):
    fmt = "{{0:0{size}b}}".format(size=size)
    return fmt.format(i)

# variable length quantity algorithm
def to_vlq(ints):
    r = []
    r.append( ints[0] * 40 + ints[1] )
    for i in ints[2:]:
        st = []
        while i:
            st.append( i & 0xff | 0x80 )
            i >>= 7
        
        st[0] ^= 0x80
        st = st[::-1]
        for ii in st:
            r.append(ii)

    return r

def from_vlq(ints):
    r = []
    r.append( ints[0]  // 40 )
    r.append( ints[0]  % 40 )
    i = 1
    while i < len(ints):
        x = 0
        while(ints[i] & 0x80):
            x |= ( ints[i] ^ 0x80 )
            x <<= 7
            i += 1

        x |= ints[i]
        r.append( x)
        i += 1

    return r

def oid_str2bin(oid):
    logging.debug(oid)
    r = bytes()
    fields = map(lambda x: int(x),oid.split('.'))
    ints = to_vlq(fields)
    for i in ints:
        r += struct.pack('B',i)
    logging.debug(binascii.hexlify(r))
    return r

def simple_create_asn1_goop(oid,sig):
    a_salg = simple_create_asn1_sig_alg(oid)
    a_sig = simple_create_asn1_sig(sig)
    return a_salg + a_sig

def simple_decode_asn1_goop(data):
    oid,offset = simple_decode_asn1_sig_alg(data)
    sig,offset = simple_decode_asn1_sig(data[offset:])
    return oid, sig, offset

def simple_create_asn1_sig_alg(oid):
    oidb = oid_str2bin(oid)

    oid_obj = ""
    oid_obj += struct.pack("BB",
                    ASN1_UTYPE_OID,
                    len(oidb)
                )
    oid_obj += oidb

    oid_params = struct.pack("BB",ASN1_UTYPE_NULL,0)

    oid_seq =""
    oid_seq += struct.pack('BB',
                    ASN1_UTYPE_SEQ, 
                    len( oid_obj ) + len( oid_params )
                )
    oid_seq += oid_obj
    oid_seq += oid_params

    logging.debug(binascii.hexlify(oid_seq))
    return oid_seq

def simple_decode_asn1_sig_alg(data,offset=0):
    oid_seq, oid_seq_length = struct.unpack('BB',data[offset:offset+2])
    assert(oid_seq == ASN1_UTYPE_SEQ)
    offset += 2
    oid_obj_type, oid_obj_length = struct.unpack('BB',data[offset:offset+2])
    assert(oid_obj_type == ASN1_UTYPE_OID)
    offset += 2
    oid_ints_encoded = []
    for i in xrange(oid_obj_length):
        oid_ints_encoded.append( struct.unpack('B',data[offset+i])[0] )

    oid_ints = from_vlq( oid_ints_encoded )
    offset += oid_obj_length

    # skip params
    offset += 2 

    return oid_ints, offset

def simple_create_asn1_sig(sigbytes):
    r = ""
    r += struct.pack("B",ASN1_UTYPE_BITSTRING)
    slength = len(sigbytes) + 1 # +1 for no padding 0
    logging.debug('length: {s}'.format(s=slength))
    if slength < 127:
        # short form
        r += struct.pack("B", slength )
    else:
        # long form
        s =[]
        while slength: 
            logging.debug(slength)
            s.append( slength & 0xff)
            slength >>= 8

        r += struct.pack('B', len(s) | 0x80)
        logging.debug(s)
        for b in s[::-1]:
            r += struct.pack('B',b)

    r += struct.pack("B",0) # zero padding
    logging.debug(binascii.hexlify(r))
    r += sigbytes
    return r

def simple_decode_asn1_sig(data,offset=0):
    sig_length = 0
    length_bytes = 0 
    utype,ulength = struct.unpack("BB",data[offset:offset+2])
    offset += 2
    assert(utype == ASN1_UTYPE_BITSTRING)
    if ulength & 0x80:
        length_bytes = ulength ^ 0x80
        for i in xrange(length_bytes):
            sig_length <<= 8
            sig_length |= struct.unpack("B",data[offset + i])[0]
    else:
        sig_length = ulength

    offset += length_bytes + 1 # +1 for meta byte

    sig_length -= 1 # for null padding
    logging.debug("sig_length: {s}".format(s=sig_length))
    sig = data[offset:offset+sig_length] 
    offset += sig_length
    offset += 1 # for null padding
    return sig, offset

def rsa_pkcs15_sign(data ,priv_key,ksize=1024):
    ksize = ksize // 8 # bits2bytes
    
    padded_sig = "\x00\x01"
    padded_sig += ( '\xff' * (ksize - 3 - len(data)) ) + '\x00'
    padded_sig += data

    assert(len(padded_sig) == ksize)

    # this gets rid of leading zeros...
    padded_sig_i = str2int16(padded_sig)
    sig = simple_rsa(padded_sig_i,priv_key)

    return sig

def simple_rsa_pkcs15_create_sig(data, halg, key, ksize=1024):
    hfunc = None
    oid = ""
    if halg == "md5":
        hfunc = hashlib.md5
        oid = OID_RSA_MD5_STR
    else:
        raise ValueError("unsupported hash function: {f}".format(f=halg))

    h = hfunc(data).digest()
    asn1_goop = simple_create_asn1_goop(oid,h)
    sig = rsa_pkcs15_sign( asn1_goop, key, ksize )
    return sig

def simple_rsa_pkcs15_verify_insecure(msg, esig, key):
    dsig = int2str( simple_rsa(esig,key) )
    logging.debug('verify decrypt: {d}'.format(d=binascii.hexlify(dsig)))
    # python int drops unecessary leading zeros...
    assert(dsig.startswith('\x00\x01\xff') or dsig.startswith('\x01\xff'))
    asn1_start = dsig.find("\xff\x00") 
    assert(asn1_start != -1 )
    asn1_data = dsig[asn1_start + 2:]
    oid, vhash , offset = simple_decode_asn1_goop(asn1_data)
    new = ""
    if oid[-4] != OID_RSA_INT:
        raise ValueError("unknown oid: {o}".format(o=oid))
    if oid[-1] == OID_RSA_MD5_INT:
        new = hashlib.md5(msg).digest()
    else:
        raise ValueError("unsupported rsa alg: {o}".format(o=oid[-1]))

    return new == vhash

def bleichenbacher_sig_forge(wanted_msg,ksize=1024):
    preamble = '\x01\xff\x00' 
    kbytes = ksize // 8

    h = hashlib.md5(wanted_msg).digest()
    hlen = len(h)

    asn1_goop = simple_create_asn1_goop(OID_RSA_MD5_STR,h)

    garbage = '\x01' * (kbytes - len(preamble) + len(asn1_goop) )
    forgery = preamble + asn1_goop + garbage
    logging.debug("hex forgery: {f}".format(f=binascii.hexlify(forgery)))
    d = str2int16( forgery )
    r = cube_root(d,near=True)
    return r

def test_vlq():
    t = map(lambda x: int(x), "1.3.6.1.4.1.311.21.20".split('.') )
    logging.debug('original: {t}'.format(t=t))
    vt = to_vlq(t)
    logging.debug('to_vlq: {t}'.format(t=vt))
    sanity = from_vlq(vt)
    logging.debug(sanity)
    assert(sanity == t)

def test_oid_str2bin():
    oid = oid_str2bin("1.3.6.1.4.1.311.21.20")
    sanity = "\x2b\x06\x01\x04\x01\x82\x37\x15\x14"
    assert(oid == sanity )

    oid = oid_str2bin("1.2.840.113549.1.1.11")
    sanity = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b"
    assert(oid == sanity)

def test_asn1():
    # pulled from x509 cert
    sanity_oid = '\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00'
    test_oid = "1.2.840.113549.1.1.11"
    x = simple_create_asn1_sig_alg(test_oid)
    assert(x == sanity_oid)
    d,offset = simple_decode_asn1_sig_alg(x)
    logging.debug(d)
    assert(".".join(map(lambda x: str(x), d)) == test_oid)
    

    sanity_sig = ""
    sanity_sig += "\x03\x82\x01\x01\x00\x59\x16\x45\xa6\x9a\x2e\x37\x79\xe4\xf6"
    sanity_sig += "\xdd\x27\x1a\xba\x1c\x0b\xfd\x6c\xd7\x55\x99\xb5\xe7\xc3\x6e"
    sanity_sig += "\x53\x3e\xff\x36\x59\x08\x43\x24\xc9\xe7\xa5\x04\x07\x9d\x39"
    sanity_sig += "\xe0\xd4\x29\x87\xff\xe3\xeb\xdd\x09\xc1\xcf\x1d\x91\x44\x55"
    sanity_sig += "\x87\x0b\x57\x1d\xd1\x9b\xdf\x1d\x24\xf8\xbb\x9a\x11\xfe\x80"
    sanity_sig += "\xfd\x59\x2b\xa0\x39\x8c\xde\x11\xe2\x65\x1e\x61\x8c\xe5\x98"
    sanity_sig += "\xfa\x96\xe5\x37\x2e\xef\x3d\x24\x8a\xfd\xe1\x74\x63\xeb\xbf"
    sanity_sig += "\xab\xb8\xe4\xd1\xab\x50\x2a\x54\xec\x00\x64\xe9\x2f\x78\x19"
    sanity_sig += "\x66\x0d\x3f\x27\xcf\x20\x9e\x66\x7f\xce\x5a\xe2\xe4\xac\x99"
    sanity_sig += "\xc7\xc9\x38\x18\xf8\xb2\x51\x07\x22\xdf\xed\x97\xf3\x2e\x3e"
    sanity_sig += "\x93\x49\xd4\xc6\x6c\x9e\xa6\x39\x6d\x74\x44\x62\xa0\x6b\x42"
    sanity_sig += "\xc6\xd5\xba\x68\x8e\xac\x3a\x01\x7b\xdd\xfc\x8e\x2c\xfc\xad"
    sanity_sig += "\x27\xcb\x69\xd3\xcc\xdc\xa2\x80\x41\x44\x65\xd3\xae\x34\x8c"
    sanity_sig += "\xe0\xf3\x4a\xb2\xfb\x9c\x61\x83\x71\x31\x2b\x19\x10\x41\x64"
    sanity_sig += "\x1c\x23\x7f\x11\xa5\xd6\x5c\x84\x4f\x04\x04\x84\x99\x38\x71"
    sanity_sig += "\x2b\x95\x9e\xd6\x85\xbc\x5c\x5d\xd6\x45\xed\x19\x90\x94\x73"
    sanity_sig += "\x40\x29\x26\xdc\xb4\x0e\x34\x69\xa1\x59\x41\xe8\xe2\xcc\xa8"
    sanity_sig += "\x4b\xb6\x08\x46\x36\xa0"

    test_sig = ""
    test_sig += "\x59\x16\x45\xa6\x9a\x2e\x37\x79\xe4\xf6\xdd\x27\x1a\xba\x1c"
    test_sig += "\x0b\xfd\x6c\xd7\x55\x99\xb5\xe7\xc3\x6e\x53\x3e\xff\x36\x59"
    test_sig += "\x08\x43\x24\xc9\xe7\xa5\x04\x07\x9d\x39\xe0\xd4\x29\x87\xff"
    test_sig += "\xe3\xeb\xdd\x09\xc1\xcf\x1d\x91\x44\x55\x87\x0b\x57\x1d\xd1"
    test_sig += "\x9b\xdf\x1d\x24\xf8\xbb\x9a\x11\xfe\x80\xfd\x59\x2b\xa0\x39"
    test_sig += "\x8c\xde\x11\xe2\x65\x1e\x61\x8c\xe5\x98\xfa\x96\xe5\x37\x2e"
    test_sig += "\xef\x3d\x24\x8a\xfd\xe1\x74\x63\xeb\xbf\xab\xb8\xe4\xd1\xab"
    test_sig += "\x50\x2a\x54\xec\x00\x64\xe9\x2f\x78\x19\x66\x0d\x3f\x27\xcf"
    test_sig += "\x20\x9e\x66\x7f\xce\x5a\xe2\xe4\xac\x99\xc7\xc9\x38\x18\xf8"
    test_sig += "\xb2\x51\x07\x22\xdf\xed\x97\xf3\x2e\x3e\x93\x49\xd4\xc6\x6c"
    test_sig += "\x9e\xa6\x39\x6d\x74\x44\x62\xa0\x6b\x42\xc6\xd5\xba\x68\x8e"
    test_sig += "\xac\x3a\x01\x7b\xdd\xfc\x8e\x2c\xfc\xad\x27\xcb\x69\xd3\xcc"
    test_sig += "\xdc\xa2\x80\x41\x44\x65\xd3\xae\x34\x8c\xe0\xf3\x4a\xb2\xfb"
    test_sig += "\x9c\x61\x83\x71\x31\x2b\x19\x10\x41\x64\x1c\x23\x7f\x11\xa5"
    test_sig += "\xd6\x5c\x84\x4f\x04\x04\x84\x99\x38\x71\x2b\x95\x9e\xd6\x85"
    test_sig += "\xbc\x5c\x5d\xd6\x45\xed\x19\x90\x94\x73\x40\x29\x26\xdc\xb4"
    test_sig += "\x0e\x34\x69\xa1\x59\x41\xe8\xe2\xcc\xa8\x4b\xb6\x08\x46\x36"
    test_sig += "\xa0"

    x = simple_create_asn1_sig( test_sig )
    assert(x == sanity_sig)
    dsig,offset = simple_decode_asn1_sig( x )
    assert( dsig == test_sig )

    # all together now
    sanity_all = sanity_oid + sanity_sig
    oid,offset = simple_decode_asn1_sig_alg( sanity_all )
    sig,offset = simple_decode_asn1_sig( sanity_all[offset:] )

    assert(".".join(map(lambda x: str(x),oid)) == test_oid)
    assert(sig == test_sig )

    # nice abstraction cause asn1 is painful
    asn1_goop = simple_create_asn1_goop(test_oid,test_sig)
    sanity_oid,sanity_sig,offset = simple_decode_asn1_goop(asn1_goop)
    
    assert(".".join(map(lambda x: str(x),sanity_oid)) == test_oid)
    assert(sig == test_sig )

if __name__ == "__main__":
    import logging
    logging.basicConfig(
            format="[%(asctime)s][%(levelname)s][%(funcName)s:%(lineno)d] %(msg)s",
            level=logging.DEBUG
            )

    test_oid_str2bin()
    test_asn1()
    test_vlq()
