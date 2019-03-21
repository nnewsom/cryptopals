from lib.challenge16 import create_query_string

def ctr_find_offset(ciphertext,control,oracle,nonce):
    control = chr(0xff) + control[1:]
    mod = oracle.encrypt( create_query_string( control ),nonce )
    assert(len(ciphertext) == len(mod))
    for i in xrange(len(mod)):
        if ciphertext[i] != mod[i]:
            return i

def ctr_flip_bit(ciphertext,offset,byte,oracle,nonce):
    ctmp = ciphertext[:offset] + chr(0xff) + ciphertext[offset+1:]
    xciphertext = oracle.encrypt(ctmp,nonce)
    modification = ord(xciphertext[offset]) ^ 0xff ^ ord(byte)
    ctmp = ciphertext[:offset] + chr(modification) + ciphertext[offset+1:]
    return ctmp
