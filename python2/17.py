from lib.challenge17 import (
    AES_BLOCKSIZE,
    aes128_cbc_pkcs7_decrypt,
    aes128_cbc_pkcs7_encrypt,
    gen_test_string,
    gen_oracle_key,
    oracle_f,
    padding_oracle
)
from lib.challenge11 import (
    random_nbytes,
)

iv = random_nbytes(AES_BLOCKSIZE)
key = gen_oracle_key()
p = gen_test_string()


print "random key: {k}".format(k=key)
print "random iv: {i}".format(i=repr(iv))

ciphertext = aes128_cbc_pkcs7_encrypt(iv,key,p)
print "ciphertext: {c}".format(c=repr(ciphertext))

p2 = aes128_cbc_pkcs7_decrypt(iv,key,ciphertext)
print repr(p)
print repr(p2)
# make sure this is working correclty
assert p == p2

oracle_txt = padding_oracle(iv,ciphertext,oracle_f,AES_BLOCKSIZE)
print "oracle txt: {}".format(repr(oracle_txt))
