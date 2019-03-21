import sys
from lib.challenge4 import hex_strings_single_xor

if len(sys.argv)< 2:
    print "{prog} file".format(prog=sys.argv[0])
    sys.exit(0)

data =  open(sys.argv[1]).read().split('\n')
key,msg = hex_strings_single_xor(data)
print msg
msg = "".join([ chr(c) for c in msg ])
print "key: {kc} ({kd})".format(kc=chr(key),kd=key)
print "msg: {msg}".format(msg=msg)
