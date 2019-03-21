from lib.challenge15 import valid_pkcs7_padding

t1 = "ICE ICE BABY\x04\x04\x04\x04"
t2 = "ICE ICE BABY\x05\x05\x05\x05"
t3 = "ICE ICE BABY\x01\x02\x03\x04"
t4 = "YELLOW SUBMARIN\x01"


print valid_pkcs7_padding(t1)
print valid_pkcs7_padding(t2)
print valid_pkcs7_padding(t3)
print valid_pkcs7_padding(t4)
