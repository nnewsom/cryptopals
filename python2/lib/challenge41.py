import binascii

def int2str(i):
    hs = hex(i).lstrip('0x').rstrip('L')
    if len(hs) % 2:
        hs = '0'+hs

    return binascii.unhexlify( hs )


