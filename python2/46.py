import base64
import binascii

from lib.challenge39 import (
        generate_seq_rsa_keypairs,
        simple_rsa
    )

from lib.challenge46 import (
        parity_oracle,
        parity_oracle_decrypt,
        set_oracle_key
    )

challenge = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
assert(len(challenge) < 128 )
challenge = int(binascii.hexlify(challenge),16)

pub,priv = generate_seq_rsa_keypairs(bitlength=1024,e=65535)

set_oracle_key(priv)
ciphertext = simple_rsa(challenge,pub)

decrypt = parity_oracle_decrypt(ciphertext, pub, parity_oracle)
assert(decrypt == challenge)
