import sys
import base64
from lib.challenge5 import repeat_xor_str
from lib.challenge6 import break_xor_repeating,normalize_hamming_distance

if len(sys.argv) < 2:
    print "{s} file".format(s=sys.argv[0])
else:
    msg = base64.b64decode(open(sys.argv[1]).read())
    print "Msg length: {d}".format(d=len(msg))
    kl = normalize_hamming_distance(msg)
    print "Key length: {d}".format(d=kl)
    key = break_xor_repeating(msg,kl)
    print "Key: {k}".format(k=repr(key))
    print repeat_xor_str(msg,key).decode('hex')
