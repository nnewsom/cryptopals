from urlparse import parse_qs
from challenge11 import random_nstr
from challenge12 import encrypt_aes128_ecb,decrypt_aes128_ecb
from challenge12 import AES_128_ECB_BLOCK

STATIC_KEY = random_nstr(AES_128_ECB_BLOCK)

def encrypt(profilestr):
    return encrypt_aes128_ecb(profilestr,STATIC_KEY)

def decrypt(profilestr):
    return decrypt_aes128_ecb(profilestr,STATIC_KEY)

def str2dict(istr):
    d = {}
    for combo in istr.split('&'):
        for k,v in combo.split('=',1):
            d[k] = v.replace('=','')
    return d

def get_block(ciphertext,blocksize,index):
    blocks = [ ciphertext[i:i+blocksize] for i in xrange(0,len(ciphertext),blocksize) ]
    return blocks[index]

def profile2str(d):
    s = ''
    s += 'email={e}'.format(e=d['user'])
    s += '&uid={u}'.format(u=d['uid'])
    s += '&role={r}'.format(r=d['role'])
    return s

def profile_for(email):
    p = {}
    p['user'] = email.replace('=','').replace('&','')
    p['uid'] = 10
    p['role'] = 'user'
    return profile2str(p)
