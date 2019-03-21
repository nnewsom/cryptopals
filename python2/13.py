from lib.challenge13 import profile_for,encrypt,decrypt,get_block
from lib.challenge12 import AES_128_ECB_BLOCK

str1= 'aaaaaaaaaaaaa@localhostadmina' # block 3 'ina&uid=10&role='
str2= 'aaaaaaaaaaaaa@localhostaaaadmin' # block 3 'admin&uid=10&rol'
str3= 'test_abcd@localhost.local' # block 1,2 'email=test_abcd@','localhost.local&'

blocksize = AES_128_ECB_BLOCK

p =  profile_for(str1)
ciphertext = encrypt(p)
part3 = get_block(ciphertext,blocksize,2)

p =  profile_for(str2)
ciphertext = encrypt(p)
part4 = get_block(ciphertext,blocksize,2)

p =  profile_for(str3)
ciphertext = encrypt(p)
part1 = get_block(ciphertext,blocksize,0)
part2 = get_block(ciphertext,blocksize,1)

chosen_ciphertext = "".join([ part1,part2,part3,part4])
plaintext = decrypt(chosen_ciphertext)
print repr(plaintext)
