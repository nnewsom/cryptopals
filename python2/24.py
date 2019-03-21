from lib.challenge18 import STRINGS
from lib.challenge24 import RngCTR
from lib.challenge11 import random_nstr
from time import time
from rand import randint
from base64 import b64decode

ctr = RngCTR(0)

for s in STRINGS:
    plaintext = b64decode(s)
    ciphertext = ctr.encrypt(plaintext)
    sanity = ctr.decrypt(ciphertext)
    assert plaintext == sanity

time_seed =
time_ctr = RngCTR( int(time.time()) + randint(40,1000))
token_plaintext = random_nstr(30)
token = time_ctr.encrypt(token_plaintext)
