from lib.challenge25 import CTR
from lib.challenge16 import create_query_string,find_admin
from lib.challenge11 import random_nstr
from lib.challenge26 import ctr_find_offset,ctr_flip_bit
from Crypto.Cipher import AES
from base64 import b64decode
import sys

nonce = 15
STATIC_KEY = random_nstr(16)
ctr = CTR(
        ECB = AES.new(STATIC_KEY,AES.MODE_ECB)
    )

atk = '#role-admin'
q = create_query_string(atk)
ciphertext = ctr.encrypt(q,nonce)

i = ctr_find_offset(ciphertext,atk,ctr,nonce)

target = ctr_flip_bit(ciphertext,i,';',ctr,nonce)
target = ctr_flip_bit(target,i+5,'=',ctr,nonce)
plaintext = ctr.decrypt(target,nonce)
print plaintext
find_admin(plaintext)
