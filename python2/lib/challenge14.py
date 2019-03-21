from Crypto.Cipher import AES
from challenge9 import PKCS7_padding
from challenge11 import random_nstr
from random import randint
from collections import Counter

AES_128_ECB_BLOCK = 16
STATIC_KEY = random_nstr(AES_128_ECB_BLOCK)
RANDOM_N_STR = random_nstr(randint(0,100))

print "Random string init: {l}".format(l=len(RANDOM_N_STR))

def decrypt_aes128_ecb(ciphertext,key):
    obj = AES.new(key,AES.MODE_ECB)
    return obj.decrypt(ciphertext).rstrip('\x04')

def encrypt_aes128_ecb(plaintext,key):
    plaintext = RANDOM_N_STR + plaintext
    plaintext = PKCS7_padding(plaintext,AES_128_ECB_BLOCK)
   # print "encrypting: "
   # print [ plaintext[i:i+AES_128_ECB_BLOCK] for i in xrange(0,len(plaintext),AES_128_ECB_BLOCK) ]
   # raw_input('e')
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

def find_block_padding( unknown_text, oracle, blocksize ):
    myblocks = ('A' * (3 * blocksize))
    block_offset = 0
    ciphertext = oracle(myblocks + unknown_text,STATIC_KEY)
    cipher_blocks = [ ciphertext[i:i+blocksize] for i in xrange(0,len(ciphertext),blocksize) ]
    counter = Counter(cipher_blocks)
    common_block,count = counter.most_common(1)[0]
    #print "most common block is: {s}\tcount: {c}".format(s=repr(common_block),c=count)

    padding = 0
    length_check =  len(oracle(unknown_text,STATIC_KEY))
    for b in xrange(1, 2 * blocksize):
        probe = 'A' * b
        ciphertext = oracle(probe + unknown_text,STATIC_KEY)
        cipher_blocks = [ ciphertext[i:i+blocksize] for i in xrange(0,len(ciphertext),blocksize) ]
        if common_block in cipher_blocks:
            #print "COMMON BLOCK FOUND"
            #print b
            padding = b - blocksize
            #print "padding should be b - blocksize: {p}".format(p=padding)
            break

    offset = ciphertext.find(common_block) # offset to our controlled block
    #print offset
    assert offset % blocksize == 0
    return (offset,'X' * padding)
    

def ecb_byte(known_text,unknown_text,oracle,blocksize,padding,offset):
    block_leak = "A"* ( blocksize - 1 - (len(known_text) % blocksize ) )# empty for leak byte + tests
    atk_len = offset + len(block_leak) + len(known_text) + 1
    d = {}
    #print "block leak is: {bl} ({d})".format(bl = repr(block_leak),d = len(block_leak))
    #print "Known text is: {kt}".format(kt=known_text)
    for i in xrange(0,256):
        chosen_plaintext = padding + block_leak + known_text + chr(i) + unknown_text
    #    print "Chosen byte: {s}".format(s = repr(chosen_plaintext[0:len(block_leak)+len(known_text)+ 2]))
        ciphertext = oracle(chosen_plaintext,STATIC_KEY)
    #    print "Generated lookup: {s}".format(s=repr(ciphertext[offset:atk_len]))
        d[ ciphertext[offset:atk_len] ]=  i

    chosen_plaintext = padding+ block_leak + unknown_text
    leak_str = repr(chosen_plaintext[offset:len(block_leak)+len(known_text)+ 1])
    #print "Leak this byte: {s} ({d})".format(
    #                            s = leak_str,
    #                            d = len(leak_str)
    #                        )
    #raw_input('?')
    ciphertext = oracle(chosen_plaintext,STATIC_KEY)
    leaked_block = ciphertext[offset:atk_len]
    if leaked_block in d:
        return chr(d[leaked_block])
    else:
        return None

def bruteforce_ecb(unknown_text,oracle,blocksize,padding,offset):
    print "Padding: {p} ({d})\tOffset: {o}".format(p=padding,d=len(padding),o=offset)
    known_text = ""
    c = ecb_byte(known_text,unknown_text,oracle,blocksize,padding,offset)
    i = 0
   # print "Found {i} byte: {c}".format(i=i,c = repr(c))
    while c:
        known_text += c
        c = ecb_byte(known_text,unknown_text,oracle,blocksize,padding,offset)
        i+=1
   #     print "Found {i} byte: {c}".format(c = repr(c),i=i)
   #     print "known text: {kt}".format(kt = repr(known_text))
   #     raw_input('!!')
    return known_text
