from lib.challenge8 import detect_AES_ECB
import sys

if len(sys.argv) < 2:
    print "{s} file".format(s=sys.argv[0])
    sys.exit()


for line in filter(None,open(sys.argv[1]).read().split('\n')):
    if detect_AES_ECB(line.decode('hex')):
        print line
