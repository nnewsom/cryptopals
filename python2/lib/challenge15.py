
def valid_pkcs7_padding(data):
    c = ord(data[-1])
    if c == 0:
        return False
    for i in xrange(1,c+1):
        if c != ord(data[-1 * i]):
            return False
    return True
