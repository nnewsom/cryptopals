from lib.challenge30 import MD4,secret_md4_mac,SECRET_KEY,generate_md4_padding
import struct

# sanity check
test = '1bee69a46ba811185c194762abaeae90'.decode('hex')
test2 = '1bee69a46ba811185c194762abaeae90'
x = MD4()
x.update('The quick brown fox jumps over the lazy dog')
assert test == x.digest()

x = MD4()
x.update('The quick brown fox jumps over the lazy dog')
assert x.hexdigest() == test2

msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
inject = ";admin=true"

x = MD4()
x.update(SECRET_KEY+msg)
mac = x.digest()

a,b,c,d = struct.unpack('<4I',mac)
print "Extracted state for md4 H(k||m): "+str(map(lambda x: hex(x), [a,b,c,d]))

print "searching for hidden key length"
for i in xrange(0,20):
    glue = generate_md4_padding('A'*i + msg)

    md4 = MD4()
    md4.update('A'*i + msg + glue)
    md4.h = [a,b,c,d]
    md4.update(inject)

    forged_mac = md4.hexdigest()
    y = MD4()
    y.update(SECRET_KEY+msg+glue+inject)
    new_mac = y.hexdigest()

    if new_mac == forged_mac:
        print "Secret key length: {d}\tforged Mac: {f}".format(d=i,f=forged_mac)
        print "successfully forged valid H(k||m): ",repr(msg+glue+inject)  
