from Crypto.Cipher import AES
from challenge9 import PKCS7_padding
from challenge11 import random_nstr

AES_128_ECB_BLOCK = 16
STATIC_KEY = random_nstr(AES_128_ECB_BLOCK)

def decrypt_aes128_ecb(ciphertext,key):
    obj = AES.new(key,AES.MODE_ECB)
    return obj.decrypt(ciphertext).rstrip('\x04')

def encrypt_aes128_ecb(plaintext,key):
    plaintext = PKCS7_padding(plaintext,AES_128_ECB_BLOCK)
    obj = AES.new(key,AES.MODE_ECB)
    return obj.encrypt(plaintext)

def determine_blocksize( message, oracle ):
    orig_len = len(oracle(message,STATIC_KEY))
    block_begin = 0
    while True:
        message = 'A'+message
        new_len = len(oracle(message,STATIC_KEY))
        if new_len > orig_len and not block_begin:
            block_begin = new_len
            orig_len = new_len
        elif new_len > orig_len and block_begin:
            return new_len - block_begin

def ecb_byte(known_text,unknown_text,oracle,blocksize):
    block_leak = "A"* ( blocksize - 1 - (len(known_text) % blocksize ) )# empty for leak byte + tests
    atk_len = len(block_leak) + len(known_text) + 1
    d = {}
    #print "block leak is: {bl} ({d})".format(bl = repr(block_leak),d = len(block_leak))
    #print "Known text is: {kt}".format(kt=known_text)
    for i in xrange(0,256):
        chosen_plaintext = block_leak + known_text + chr(i) + unknown_text
        #print "Chosen byte: {s}".format(s = repr(chosen_plaintext[0:len(block_leak)+len(known_text)+ 2]))
        ciphertext = oracle(chosen_plaintext,STATIC_KEY)
        d[ ciphertext[0:atk_len] ]=  i

    chosen_plaintext = block_leak + unknown_text
    leak_str = repr(chosen_plaintext[0:len(block_leak)+len(known_text)+ 1])
    #print "Leak byte: {s} ({d})".format(
    #                            s = leak_str,
    #                            d = len(leak_str)
    #                        )
    ciphertext = oracle(chosen_plaintext,STATIC_KEY)
    leaked_block = ciphertext[0:atk_len]
    if leaked_block in d:
        return chr(d[leaked_block])
    else:
        return None

def bruteforce_ecb(unknown_text,oracle,blocksize):
    padding = "X"*(len(unknown_text) % blocksize) 
    #print "Padding: {p} ({d})".format(p=padding,d=len(padding))
    unknown_text =  padding + unknown_text # make it align w/ blocksize
    known_text = ""
    c = ecb_byte(known_text,unknown_text,oracle,blocksize)
    #i = 0
    #print "Found {i} byte: {c}".format(i=i,c = repr(c))
    while c:
        known_text += c
        c = ecb_byte(known_text,unknown_text,oracle,blocksize)
        #i+=1
        #print "Found {i} byte: {c}".format(c = repr(c),i=i)
        #print "known text: {kt}".format(kt = repr(known_text))
    return known_text[len(padding):]
