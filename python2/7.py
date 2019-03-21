from Crypto.Cipher import AES
import base64
import sys

if len(sys.argv) < 2:
    print "{p} key message_file".format(p=sys.argv[0])
    sys.exit()

edata = base64.b64decode(open(sys.argv[2]).read())
obj = AES.new(sys.argv[1],AES.MODE_ECB)
d_data = obj.decrypt(edata)
print d_data
