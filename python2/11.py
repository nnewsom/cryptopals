from lib.challenge11 import random_encrypt
from lib.challenge8 import detect_AES_ECB
import sys

if len(sys.argv) < 2:
    print "{p} plaintext_file".format(p=sys.argv[0])
    sys.exit()


data = open(sys.argv[1]).read()
method,edata = random_encrypt(data)
is_ECB = detect_AES_ECB(edata)

if  is_ECB and method == "ECB":
    print "correct guess as ECB"
elif not is_ECB and method == "CBC":
    print "correct guess as CBC"
else:
    print "incorrect guess"
    print "ECB detection: "+str(is_ECB)
    print "Random method: "+method
