from lib.challenge3 import *
import binascii
import sys

if len(sys.argv)< 2:
    print("{prog} hexstring".format(prog=sys.argv[0]))
    sys.exit(0)

data = sys.argv[1].decode('hex')
key,msg = break_xor_byte(data)
msg = "".join([ chr(c) for c in msg ])
print "key: {kc} ({kd})".format(kc=chr(key),kd=key)
print "msg: {msg}".format(msg=msg)
