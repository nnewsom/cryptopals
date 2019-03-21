def PKCS7_padding(msg,blk_size):
    pad_len = blk_size - len(msg) % blk_size if len(msg) % blk_size != 0 else 0
    # cannot have no padding, need to know when padding is complete
    if pad_len == 0:
        pad_len = blk_size
    for i in xrange(0,pad_len):
        msg += chr(pad_len)
    return msg
