import logging
import binascii
import struct

from challenge7 import (
        BLKSZ,
        aes128_encrypt_block,
        aes128_decrypt_block,
        init_global_sbox,
    )

from challenge2 import xor_str

def aes128_cbc_enc(iv,key,msg):
    init_global_sbox()
    ciphertext = ""
    mblocks = [ msg[i:i+BLKSZ] for i in xrange(0,len(msg),BLKSZ) ]

    prev = iv
    for mb in mblocks:
        xmb = xor_str(prev,mb)
        cb = aes128_encrypt_block(key,xmb)
        prev = cb
        ciphertext += cb
    return ciphertext

def aes128_cbc_dec(iv,key,ciphertext):
    init_global_sbox()
    plaintext = ""
    cblocks = [ ciphertext[i:i+BLKSZ] for i in xrange(0,len(ciphertext),BLKSZ) ]
    
    for i in xrange(len(cblocks)-1,0,-1):
        t = aes128_decrypt_block(key,cblocks[i])
        pb = xor_str(t, cblocks[i-1])
        plaintext = pb + plaintext

    xcb = xor_str(cblocks[0], iv)
    pb = aes128_decrypt_block(key,xcb)
    plaintext = pb + plaintext

    return plaintext

def test_aes128_cbc():
    import hashlib
    init_global_sbox()

    iv = '\x00' * BLKSZ
    k = hashlib.md5('hello').digest()
    m = 'YELLOW SUBMARINEYELLOW SUBMARINEYELLOW SUBMARINE'
    # openssl enc -aes-128-cbc -in test -k hello -nosalt -nopad -md md5 -iv 0
    s = ''
    s += 'afcc5e0f85b858409ce061a5e987a0c8a6'
    s += '34c20322e91150bac83a69a1f2878b00a30'
    s += '4f5250aba8f9fbf0a91c32d2ce7'
    
    ctxt = aes128_cbc_enc( iv ,k,m)
    ctxth = binascii.hexlify(ctxt)
    logging.debug("ctxt: {}".format(ctxth))
    logging.debug("sane: {}".format(s))
    assert( s == ctxth )
    ptxt = aes128_cbc_dec( iv, k, ctxt)
    logging.debug("plaintext: {}".format(ptxt))
    assert( ptxt == m )

if __name__ == "__main__":
    logging.basicConfig(
            format="[%(asctime)s][%(levelname)s][%(funcName)s:%(lineno)d] %(msg)s",
            level=logging.DEBUG
    )
    test_aes128_cbc()
