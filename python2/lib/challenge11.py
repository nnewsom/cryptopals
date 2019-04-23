import random
import string

from lib.challenge7 import (
        aes128_ecb_encrypt,
        aes128_ecb_decrypt
    )
from lib.challenge9 import PKCS7_padding
from lib.challenge10 import (
        aes128_cbc_encrypt,
        aes128_cbc_decrypt
    )

def random_nbytes(n):
    return open('/dev/urandom').read(n)

def random_nstr(n):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))

def random_encrypt_cbc(data):
    return aes128_cbc_enc(random_nbytes(16),random_nbytes(16),data)

def random_encrypt_ecb(data):
    return aes128_ecb_encrypt(random_nbytes(16),data)

def random_encrypt(data):
    method = random.choice(['CBC','ECB'])
    data = "{r1}{d}{r2}".format(
                r1=random_nstr(random.choice( [ i for i in range(5,11)] )),
                d = data,
                r2=random_nstr(random.choice( [ i for i in range(5,11)] ))
            )
    data = PKCS7_padding(data,16)
    edata = ""
    if method == 'CBC':
        edata = random_encrypt_cbc(data)
    elif method == 'ECB':
        edata = random_encrypt_ecb(data)
    return (method,edata)
