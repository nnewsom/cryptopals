from lib.challenge18 import CTR,STRINGS
from Crypto.Cipher import AES
from base64 import b64decode


ctr = CTR(
        ECB = AES.new("YELLOW SUBMARINE",AES.MODE_ECB)
    )

test = b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
plaintext = ctr.decrypt(test,0)
print "ciphertext: ",repr(test)
print "plaintext: ",plaintext

for s in STRINGS:
    plaintext = b64decode(s)
    ciphertext = ctr.encrypt(plaintext,0)
    sanity = ctr.decrypt(ciphertext,0)
    assert plaintext == sanity

print "sanity checks passed for strings"
