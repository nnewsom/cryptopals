import logging
import binascii

from lib.challenge42 import ( 
        simple_rsa_pkcs15_create_sig,
        simple_rsa_pkcs15_verify_insecure,
        bleichenbacher_sig_forge
    )
from lib.challenge39 import (
        generate_seq_rsa_keypairs,
        simple_rsa
    )
from lib.challenge41 import int2str

logging.basicConfig(
            format="[%(asctime)s][%(levelname)s][%(filename)s:%(lineno)d] %(msg)s",
            level=logging.INFO
        )

pub_key, priv_key = generate_seq_rsa_keypairs(bitlength=1024,e=3)
logging.info("pub: {}".format(pub_key))
logging.info("priv: {}".format(priv_key))

msg = "hi mom!"
sig = simple_rsa_pkcs15_create_sig(
            data =msg,
            halg = "md5",
            key = priv_key,
            ksize =1024
        )

logging.info("msg: {m}".format(m=msg))
logging.info("sig: {s}".format(s=hex(sig)))

valid_sig = simple_rsa_pkcs15_verify_insecure( msg, sig, pub_key )
logging.info("valid sig: {v}".format(v=valid_sig))

forge = bleichenbacher_sig_forge("hi mom!")
logging.info("forgery: {f}".format(f=hex(forge)))
valid_sig = simple_rsa_pkcs15_verify_insecure( msg, forge, pub_key )
logging.info("valid sig: {v}".format(v=valid_sig))
