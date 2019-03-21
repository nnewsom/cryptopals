from lib.challenge2 import *
import sys

if len(sys.argv) < 3:
    print "{prog} val1 val2".format(prog=sys.argv[0])
    sys.exit(0)

val1 = sys.argv[1].decode("hex")
val2 = sys.argv[2].decode("hex")

r = fixed_xor(val1,val2)
print r
print "".join([ chr(h) for h in r])
