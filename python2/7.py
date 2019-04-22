import base64
import sys

from lib.challenge7 import aes128_ecb_decrypt

ciphertext = base64.b64decode(open('./7.txt').read())
k = "YELLOW SUBMARINE"
plaintext = aes128_ecb_decrypt(k,ciphertext)
print repr(plaintext)
