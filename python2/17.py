from lib.challenge17 import encrypt_aes_cbc,decrypt_aes_cbc
from lib.challenge17 import padding_oracle, gen_test_string
from lib.challenge17 import AES_BLOCKSIZE,RANDOM_KEY


p = gen_test_string()
print "using random key: ",RANDOM_KEY
iv,ciphertext = encrypt_aes_cbc(p)
print "random iv: ",repr(iv)
print "ciphertext: ",repr(ciphertext)

p2 = decrypt_aes_cbc(iv,ciphertext)
assert p == p2

plaintext = padding_oracle(iv,ciphertext,decrypt_aes_cbc,AES_BLOCKSIZE)
print "plaintext: ",repr(plaintext)
