from Crypto.Cipher import AES
from lib.challenge9 import PKCS7_padding
import random
import string

def random_nbytes(n):
    return open('/dev/urandom').read(n)

def random_nstr(n):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))

def random_encrypt_cbc(data):
    obj = AES.new(random_nstr(16),AES.MODE_CBC,random_nbytes(16))
    return obj.encrypt(data)

def random_encrypt_ecb(data):
    obj = AES.new(random_nbytes(16),AES.MODE_ECB)
    return obj.encrypt(data)

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
