from collections import Counter
AES_ECB_BLOCK_LENGTH = 16

def detect_AES_ECB(data):
    blocks = [ data[i:i+AES_ECB_BLOCK_LENGTH] for i in xrange(0,len(data),AES_ECB_BLOCK_LENGTH) ]
    c = Counter(blocks)
    block,count = c.most_common(1)[0]
    if count > 1:
        return True
    else:
        return False
