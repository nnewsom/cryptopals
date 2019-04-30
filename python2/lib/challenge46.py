import binascii
import math

from challenge39 import (
        generate_seq_rsa_keypairs,
        simple_rsa
    )

from challenge41 import (
        int2str
    )

challenge46_priv = None

def set_oracle_key(priv):
    global challenge46_priv 
    challenge46_priv = priv 

def parity_oracle(ciphertext):
    global challenge46_priv
    plaintext = simple_rsa(ciphertext,challenge46_priv)
    return plaintext & 1 == 0


def bitlength(c):
    bl = 0
    while c:
        bl +=1
        c >>= 1
    return bl

# if odd, wrapped mod
# if even, it's less than half

def parity_oracle_decrypt(ciphertext, pub, oracle, hollywood=True):
    e,n = pub

    up = n
    low = 0 
    c =  1
    for _ in xrange( bitlength(ciphertext) + 1 ) :
        c *= 2
        mm = simple_rsa(c,pub)
        if oracle(ciphertext * mm):
            up = (up+low)/2
        else:
            low = (up+low)/2
        if hollywood:
            print repr(int2str(up))
    return up

def test_parity_oracle():
    pub,priv = generate_seq_rsa_keypairs(bitlength=1024,e=65535)
    set_oracle_key(priv)

    test_text = "TESTME123"
    test_i = int(binascii.hexlify(test_text),16)
    logging.debug("test: {s} ({i})".format(s=test_text,i=test_i))

    cipher = simple_rsa(test_i,pub)
    logging.debug("cipher: {c}".format(c=cipher))
    v = parity_oracle(cipher)
    logging.debug("oracle: {v}".format(v=v))
    assert(v == False)


if __name__ == "__main__":
    import logging
    logging.basicConfig(
            format="[%(asctime)s][%(levelname)s][%(funcName)s:%(lineno)d] %(msg)s",
            level=logging.DEBUG
            )

    test_parity_oracle()
