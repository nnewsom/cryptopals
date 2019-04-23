from base64 import b64decode
from random import choice
        
from challenge9 import PKCS7_padding
from challenge10 import (
        aes128_cbc_encrypt,
        aes128_cbc_decrypt
    )
from challenge11 import (
        random_nstr,
        random_nbytes
    )
from challenge15 import valid_pkcs7_padding

AES_BLOCKSIZE = 16

TEST_STRINGS = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
]

def gen_test_string():
    return b64decode(choice(TEST_STRINGS))

def aes128_cbc_pkcs7_encrypt(iv,key,plaintext):
    plaintext = PKCS7_padding(plaintext,AES_BLOCKSIZE)
    iv = random_nbytes(AES_BLOCKSIZE)
    if valid_pkcs7_padding(plaintext):
        ciphertext = aes128_cbc_encrypt(iv,key,plaintext)
        return ciphertext
    else:
        raise('Invalid PKCS7 padding')

def aes128_cbc_pkcs7_decrypt(iv,key,ciphertext):
    plaintext = aes128_cbc_decrypt(iv,key,ciphertext)
    if valid_pkcs7_padding(plaintext):
        padding = ord(plaintext[-1])
        return plaintext[: -1 * padding]
    else:
        raise('Invalid PKCS7 padding')

ORACLE_KEY = ""
def gen_oracle_key():
    global ORACLE_KEY
    ORACLE_KEY = random_nstr(16)
    return ORACLE_KEY
    
def oracle_f(b0,b1):
    return aes128_cb_pkcs7_decrypt(b0,ORACLE_KEY,b1)

def padding_oracle(iv,ciphertext,oracle,blksize):
    blocks = [iv] + [ ciphertext[i:i+blksize] for i in xrange(0,len(ciphertext),blksize)]
    padded = False

    msg = ""
    for b0,b1 in [ (blocks[i],blocks[i+1]) for i in xrange(0,len(blocks)-1)]:
        padding = [ '\x00' for i in xrange(blksize)]
        knowntext = ['\x00' for i in xrange(blksize)]
        tblock = [ c for c in b0 ]
        atk_start = 1

        try:
            oracle(b0,b1)
            padded = True
        except:
            padded = False

        #set up padding
        for atk_byte in xrange(atk_start,blksize+1):
            for k in xrange(1,atk_byte+1):
                padding[-1 * k] = chr(atk_byte)

            xor_magic_pairs = zip(tblock,padding,knowntext)
            atk = []
            for x,y,z in xor_magic_pairs:
                atk.append( ord(x) ^ ord(y) ^ ord(z) )
            
            #brute force byte
            for i in xrange(0,256):
                    atk[-1*atk_byte] = ord(b0[-1 * atk_byte]) ^ i
                    satk = "".join(map(lambda x: chr(x), atk))
                    try:
                        oracle(satk,b1)
                        discov = i ^ atk_byte
                        if padded and discov == 1:
                            continue #FP
                        knowntext[-1*atk_byte] = chr(discov)
                        break
                    except Exception as e:
                        continue
        if knowntext:
            msg += "".join(knowntext)

    return msg
