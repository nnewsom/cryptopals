from lib.challenge16 import encrypt_aes128_cbc,decrypt_aes128_cbc
from lib.challenge16 import create_query_string,find_admin,modification_offset
from lib.challenge16 import flip_byte


atk = 'AABBBBBBBBBBBBBBBB#role-admin'
q = create_query_string(atk)
ciphertext = encrypt_aes128_cbc(q)

offset = modification_offset(ciphertext,'#role')
ciphertext = flip_byte(ciphertext,offset,';')

offset2 = modification_offset(ciphertext,'-admin')
ciphertext = flip_byte(ciphertext,offset2,'=')

plaintext = decrypt_aes128_cbc(ciphertext)
print plaintext
find_admin(plaintext)
