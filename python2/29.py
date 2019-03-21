from lib.challenge2 import random_nstr
from lib.challenge28 import SECRET_KEY,secret_mac
from lib.challenge29 import Sha1Hash
from lib.challenge29 import generate_md_padding

msg = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
inject = ';admin=true'

mac = secret_mac(msg)

print "original message: ", msg
print "original mac: ",mac
a,b,c,d,e =  map(lambda x: int(x,16), [ mac[i:i+8] for i in xrange(0,len(mac),8)] )
print "Extracted state from H(k||m): "+str(map(lambda x: hex(x), [a,b,c,d,e]))

print "searching for hidden key length"
for i in xrange(0,100):
    glue = generate_md_padding('A'*i + msg)

    sha1 = Sha1Hash()
    sha1.update('A'*i + msg + glue)
    sha1._h = ( a,b,c,d,e )
    sha1.update(inject)

    forged_mac = sha1.hexdigest()

    new_mac = secret_mac(msg+glue+inject)

    if new_mac == forged_mac:
        print "Secret key length: {d}\tforged Mac: {f}".format(d=i,f=forged_mac)
        print "successfully forged valid H(k||m): ",repr(msg+glue+inject)
