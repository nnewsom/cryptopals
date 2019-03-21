import random
import string

def xor_str(xs,ys):
    return "".join([ chr(ord(x) ^ ord(y)) for x,y in zip(xs,ys) ])

def random_nstr(n):
    return ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))

def random_nbytes(n):
    return open('/dev/urandom').read(n)
