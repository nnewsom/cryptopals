import base64

from lib.challenge10 import aes128_cbc_dec

ctxt = base64.b64decode(open('./data/10.txt').read())
iv = "\x00" *16
k = "YELLOW SUBMARINE"
ptxt = aes128_cbc_dec(iv,k,ctxt)
print repr(ptxt)
