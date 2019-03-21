from Crypto.Cipher import AES
import base64
import sys

if len(sys.argv) < 2:
    print "{p} message_file".format(p=sys.argv[0])
    sys.exit()

edata = base64.b64decode(open(sys.argv[1]).read())
obj = AES.new('YELLOW SUBMARINE',AES.MODE_CBC,'\x00' * 16)
d_data = obj.decrypt(edata)
print d_data
