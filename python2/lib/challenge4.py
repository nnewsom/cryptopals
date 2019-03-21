import string
from challenge3 import break_single_xor,score

def printable(msg):
    return all(c in string.printable for c in msg)

def hex_strings_single_xor(data):
    def key(p):
        return score(p[1])

    return max( [break_single_xor(d.decode('hex')) for d in data], key=key )

