from lib.challenge18 import CTR
from lib.challenge6 import break_xor_repeating
from lib.challenge2 import xor_str

from Crypto.Cipher import AES
from base64 import b64decode


ctr = CTR(
        ECB = AES.new("YELLOW SUBMARINE",AES.MODE_ECB)
    )

ciphertexts = []
for s in filter(None,open('/tmp/crypto/20.txt').read().split('\n')):
    plaintext = b64decode(s)
    ciphertexts.append( ctr.encrypt(plaintext,0) )

min_ciphertext = min(ciphertexts,key=lambda x: len(x))
kl = len(min_ciphertext)
combined_ciphertext = "".join(map(lambda x: x[:kl],ciphertexts))
key = break_xor_repeating(combined_ciphertext,kl)
print repr(key)
print xor_str(key,min_ciphertext)
