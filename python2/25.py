from lib.challenge25 import CTR,STRINGS
from lib.challenge11 import random_nstr
from Crypto.Cipher import AES
from base64 import b64decode
import sys

ctr = CTR(
        ECB = AES.new("YELLOW SUBMARINE",AES.MODE_ECB)
    )

nonce = 15

test = 'A'* 45
ciphertext = ctr.encrypt(test,nonce)
plaintext = ctr.decrypt(ciphertext,nonce)
assert(plaintext == test)

ctr = CTR(
        ECB = AES.new(random_nstr(16),AES.MODE_ECB)
    )

plaintext = random_nstr(100)
ciphertext = ctr.encrypt(plaintext,nonce)

knowntext = ""

for i in xrange(len(ciphertext)):
    lookup = {}
    for j in xrange(255):
        edited = ctr.edit(ciphertext,nonce,i,chr(j))
        lookup[edited[i]] = chr(j)
    if ciphertext[i] in lookup:
        knowntext += lookup[ ciphertext[i] ]

print repr(knowntext)
assert ( plaintext == knowntext )
