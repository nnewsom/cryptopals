from base64 import b64decode
from random import choice
from challenge11 import random_nstr,random_nbytes
from challenge15 import valid_pkcs7_padding
from challenge9 import PKCS7_padding
from challenge16 import encrypt_aes128_cbc,decrypt_aes128_cbc
from Crypto.Cipher import AES

AES_BLOCKSIZE = 16
RANDOM_KEY = random_nstr(AES_BLOCKSIZE)

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

def encrypt_aes_cbc(plaintext):
    plaintext = PKCS7_padding(plaintext,AES_BLOCKSIZE)
    iv = random_nbytes(AES_BLOCKSIZE)
    if valid_pkcs7_padding(plaintext):
        obj = AES.new(RANDOM_KEY,AES.MODE_CBC,iv)
        return (iv, obj.encrypt(plaintext))
    else:
        raise('Invalid PCKS7 padding')

def decrypt_aes_cbc(iv,ciphertext):
    obj = AES.new(RANDOM_KEY,AES.MODE_CBC,iv)
    plaintext = obj.decrypt(ciphertext)
    if valid_pkcs7_padding(plaintext):
        padding = ord(plaintext[-1])
        return plaintext[: -1 * padding]
    else:
        raise('Invalid PCKS7 padding')

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
