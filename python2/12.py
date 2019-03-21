import sys
import base64
from lib.challenge12 import bruteforce_ecb,encrypt_aes128_ecb,determine_blocksize

unknown_text = base64.b64decode(open('/tmp/crypto/challenge12.txt').read())
blocksize = determine_blocksize(unknown_text, encrypt_aes128_ecb)
print "Block size is {d}".format(d = blocksize)
print bruteforce_ecb(unknown_text,encrypt_aes128_ecb,blocksize)
print "done"
