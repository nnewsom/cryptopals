def repeat_xor_str(msg,key):
    r = []
    ki = 0
    for c in msg:
        r.append( ord(c) ^ ord( key[ki % len(key)] ))
        ki+=1
    return "".join([ "%0.2X" % i for i in r])

def repeat_xor_ints(key,ints):
    r = []
    ki =0
    for i in ints:
        r.append( i ^ ord(key[ki % len(key)]) )
        ki+=1
    return r
