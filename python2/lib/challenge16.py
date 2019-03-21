from Crypto.Cipher import AES
from challenge15 import valid_pkcs7_padding
from challenge11 import random_nstr
from challenge9 import PKCS7_padding

AES_BLOCKSIZE = 16
RANDOM_KEY = random_nstr(AES_BLOCKSIZE)
STATIC_IV = "\x00"* AES_BLOCKSIZE

def encrypt_aes128_cbc(plaintext):
    plaintext = PKCS7_padding(plaintext,AES_BLOCKSIZE)
    if valid_pkcs7_padding:
        obj = AES.new(RANDOM_KEY,AES.MODE_CBC,STATIC_IV)
        return obj.encrypt(plaintext)
    else:
        raise('Invalid PKCS7 padding')

def decrypt_aes128_cbc(ciphertext):
    obj = AES.new(RANDOM_KEY,AES.MODE_CBC,STATIC_IV)
    plaintext = obj.decrypt(ciphertext)
    # get rid of PKCS7 padding
    padding = ord(plaintext[-1])
    plaintext = plaintext[: -1 * padding]
    return plaintext

def create_query_string(atk_input):
    atk_input = atk_input.replace('=','').replace(';','')
    prefix = "comment1=cooking MCs;userdata="
    postfix = ";comment2= like a pound of bacon"
    return prefix + atk_input + postfix

def parse_query(query):
    fields = query.split(';')
    d = {}
    for param in fields:
        k,v = param.split('=')
        d[k] = v
    return d

def modification_offset(ciphertext,findtxt):
    orig_plaintext = decrypt_aes128_cbc(ciphertext)
    find_start = orig_plaintext.find(findtxt)

    if find_start == -1:
        raise("could not find findtxt")

    for i in xrange(0,len(ciphertext)):
        ctmp = [c for c in ciphertext]
        ctmp[i] = chr(0xff)
        ctmp = "".join(ctmp)

        plaintext = decrypt_aes128_cbc(ctmp)
        if plaintext[find_start] != orig_plaintext[find_start]:
            return i
    return -1

def flip_byte(ciphertext,offset,target):
    ctmp = ciphertext[:offset] + chr(0xff) + ciphertext[offset+1:]

    plaintext = decrypt_aes128_cbc(ctmp)
    result = plaintext[offset+AES_BLOCKSIZE]
    mod = ord(result) ^ 0xff  ^ ord(target)
    
    ctmp = ciphertext[:offset] + chr(mod) + ciphertext[offset+1:]
    plaintext = decrypt_aes128_cbc(ctmp)
    assert plaintext[offset + AES_BLOCKSIZE] == target
    return ctmp

def find_admin(query):
    d = parse_query(query)
    print d
    if 'role' in d:
        if d['role'] == 'admin':
            print "SUCCESS"
        print "{k}={v}".format(k='role',v=d['role'])
    else:
        print "no admin"

