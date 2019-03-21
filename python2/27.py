from lib.challenge27 import encrypt_aes128_cbc,verify_oracle,RANDOM_KEY
from lib.challenge2 import xor_str
from lib.challenge11 import random_nstr

BLKSZ = 16

print "key: ",RANDOM_KEY
test = random_nstr(100)
print "input: ",test
ciphertext = encrypt_aes128_cbc(test)
print repr(ciphertext)
blocks = [ ciphertext[i:i+BLKSZ] for i in xrange(0,len(ciphertext),BLKSZ)]
modified = blocks[0] + '\x00'*BLKSZ + blocks[0] + "".join(blocks[2:])
isplaintext, plaintext = verify_oracle(modified)
pblocks = [ plaintext[i:i+BLKSZ] for i in xrange(0,len(plaintext),BLKSZ)]
key = xor_str(pblocks[0],pblocks[2])
print "recovered key: ",repr(key)
