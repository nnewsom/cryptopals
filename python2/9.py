from lib.challenge9 import PKCS7_padding
import sys

if len(sys.argv) < 3:
    print "{s} block_size data".format(s=sys.argv[0])
    sys.exit()

print repr(PKCS7_padding(
            msg = sys.argv[2],
            blk_size = int(sys.argv[1])
    ))
