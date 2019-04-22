import binascii
import struct

# https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
# https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
# www.samium.org/galois.html

WIKI_TBL = """00 63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76
10 ca 82 c9 7d fa 59 47 f0 ad d4 a2 af 9c a4 72 c0
20 b7 fd 93 26 36 3f f7 cc 34 a5 e5 f1 71 d8 31 15
30 04 c7 23 c3 18 96 05 9a 07 12 80 e2 eb 27 b2 75
40 09 83 2c 1a 1b 6e 5a a0 52 3b d6 b3 29 e3 2f 84
50 53 d1 00 ed 20 fc b1 5b 6a cb be 39 4a 4c 58 cf
60 d0 ef aa fb 43 4d 33 85 45 f9 02 7f 50 3c 9f a8
70 51 a3 40 8f 92 9d 38 f5 bc b6 da 21 10 ff f3 d2
80 cd 0c 13 ec 5f 97 44 17 c4 a7 7e 3d 64 5d 19 73
90 60 81 4f dc 22 2a 90 88 46 ee b8 14 de 5e 0b db
a0 e0 32 3a 0a 49 06 24 5c c2 d3 ac 62 91 95 e4 79
b0 e7 c8 37 6d 8d d5 4e a9 6c 56 f4 ea 65 7a ae 08
c0 ba 78 25 2e 1c a6 b4 c6 e8 dd 74 1f 4b bd 8b 8a
d0 70 3e b5 66 48 03 f6 0e 61 35 57 b9 86 c1 1d 9e
e0 e1 f8 98 11 69 d9 8e 94 9b 1e 87 e9 ce 55 28 df
f0 8c a1 89 0d bf e6 42 68 41 99 2d 0f b0 54 bb 16"""

COL_MATRIX = [
    [ 2, 3, 1, 1],
    [ 1, 2, 3, 1],
    [ 1, 1, 2, 3],
    [ 3, 1, 1, 2]
]

ICOL_MATRIX = [
    [ 0xe, 0xb, 0xd, 0x9],
    [ 0x9, 0xe, 0xb, 0xd],
    [ 0xd, 0x9, 0xe, 0xb],
    [ 0xb, 0xd, 0x9, 0xe]
]

# 10 rounds total. -1 since final is manual
AES_128_ROUNDS = 9
AES_128_KEYWORDS_N = 44

# 12 rounds. -1 since final is manual
AES_192_ROUNDS = 11
AES_192_KEYWORDS_N = 52

# 14 rounds total. -1 since final is manual
AES_256_ROUNDS = 13
AES_256_KEYWORDS_N = 60

BLKSZ = 16
WORDSZ = 4

g_sbox = None
g_isbox = None

def init_global_sbox():
    global g_sbox,g_isbox
    sbox = {}
    rows = filter(None,WIKI_TBL.split("\n"))
    for r in rows:
        columns = r.split(' ')
        k = int(columns.pop(0),16)
        for ci,c in enumerate(columns):
            sbox[ k | ci ] = int(c,16)
            
    assert(sbox[0x12] == 0xc9)
    assert(sbox[0x33] == 0xc3)
    assert(sbox[0x84] == 0x5f)
    isbox = {v:k for k,v in sbox.items()}
    
    g_sbox = sbox
    g_isbox = isbox

    return sbox,isbox

def shift_row_right(r,l):
    s = [ x for x in r ]
    for _ in xrange(l):
        x = s.pop()
        s.insert(0,x)
    return s

def shift_row_left(r,l):
    s = [ x for x in r ]
    for _ in xrange(l):
        x = s.pop(0)
        s.append(x)
    return s

def shift_rows_left(matrix):
    for i in xrange(1,len(matrix)):
        matrix[i] = shift_row_left(matrix[i],i)
    return matrix 

def shift_rows_right(matrix):
    for i in xrange(1,len(matrix)):
        matrix[i] = shift_row_right(matrix[i],i)
    return matrix 

def get_row(matrix,i):
    return matrix[i]

def get_column(matrix,i):
    v = []
    for r in matrix:
        v.append(r[i])
    return v

def xor_mmulti_op(row,column):
    r = 0
    for rv,cv in zip(row,column):
        r ^= gf_mul(rv,cv)
    return r

# this isn't correct
# all multiplication is galois field based
# all addition is XOR
def add_mmulti_op(row,column):
    r = 0
    for rv,cv in zip(row,column):
        r += rv * cv
    return r
    
def matrix_multi(state, m1):
    r = [ [ 0 for i in xrange(WORDSZ)] for i in xrange(WORDSZ)]
    for ci in xrange(WORDSZ):
        col = get_column(state,ci)
        for ri in xrange(WORDSZ):
            row = m1[ri]
            r[ri][ci] = xor_mmulti_op(row,col)
    return r

def print_tbl(t,inhex=False):
    if inhex:
        for i,r in enumerate(t):
            v = struct.unpack('>I',"".join(map(lambda x: chr(x), r)))[0]
            print "{i}:{v}".format(i=i,v=hex(v))
    else:
        for i,r in enumerate(t):
            print "{i}:{r}".format(i=i,r=map(lambda x: hex(x), r ))

# rijndael galois field ops

def gf_add(a,b):
    return (a & 0xff) ^ ( b & 0xff)

def gf_sub(a,b):
    return gf_add(a,b)

def gf_mul(a,b):
    r = 0
    a = a & 0xff
    b = b & 0xff
    for _ in xrange(8):
        if b & 0x1:
            r ^= a
        a_high = a & 0x80
        a = ( a << 1 ) & 0xff
        if a_high:
            a ^= 0x1b
        b >>= 1
    return r

def test_gf():
    logging.debug("testing gf functions")
    r = gf_mul(7,3)
    assert(r == 9)
    r = gf_add(40,30)
    assert(r == 54)

# N = length of key in 32 bit words
# 4 128, 6 for 192, 8 for 256
# K = original 32 bit words
# r = # of round. 11 128, 13 192, 15 256

# round constant, 3 right most bytes are always 0
def g(keyword,rcon):
    global g_sbox
    rotkeyword = shift_row_left(keyword,1) # 1: << 8
    w = []
    for b in rotkeyword:
        w.append( g_sbox[b] )

    w[0] ^= rcon 
    rcon = gf_mul(rcon,2)
    return w,rcon 

def xor_lists(l1,l2):
    s = []
    for v1,v2 in zip(l1,l2):
        s.append( v1 ^ v2 )
    return s

def test_xor_lists():
    logging.debug("testing xor lists")
    l1 = [ 0x0f, 0x0f, 0x0f, 0x0f ]
    l2 = [ 0x0f, 0x0f, 0x0f, 0x0f ]
    
    l3 = xor_lists(l1,l2)
    for e in l3:
        assert(e == 0)

    n = 0x44 ^ 0x0f
    l1 = [ n , n, n, n ]
    l2 = [ 0x0f, 0x0f, 0x0f, 0x0f ]
    
    l3 = xor_lists(l1,l2)
    for e in l3:
        assert(e == 0x44)


def test_matrix_multi():
    logging.debug("testing matrix multi")
    state = [
            [ 0x33, 0x51, 0x79, 0x0A ],
            [ 0x8B, 0x66, 0x8F, 0x3F ],
            [ 0x76, 0x7D, 0xEB, 0xBE ],
            [ 0x20, 0x92, 0xC2, 0x67 ]
        ]

    sanity = [
            [ 0xB6, 0xE7, 0x51, 0x8C],
            [ 0x84, 0x88, 0x98, 0xCA],
            [ 0x34, 0x60, 0x66, 0xFB],
            [ 0xE8, 0xD7, 0x70, 0x51] 
        ]

    x = matrix_multi(state,COL_MATRIX)
    assert(x == sanity)

def test_shift_row():
    x = [ 1, 2, 3 , 4]
    x1 = shift_row_right(x,1)
    assert( x1 == [ 4,1,2,3] )
    x2 = shift_row_right(x,2)
    assert( x2 == [ 3,4,1,2] )
    x3 = shift_row_right(x,3)
    assert( x3 == [ 2,3,4,1] )

    x1 = shift_row_left(x,1)
    assert( x1 == [ 2,3,4,1] )
    x2 = shift_row_left(x,2)
    assert( x2 == [ 3,4,1,2 ] )
    x3 = shift_row_left(x,3)
    assert( x3 == [ 4,1,2,3 ] )

def keyschedule(key,keysz=128):
    wordn = AES_128_KEYWORDS_N
    if keysz == 192:
        wordn = AES_192_KEYWORDS_N
    elif keysz == 256:
        wordn = AES_256_KEYWORDS_N

    if len(key) != BLKSZ:
        key = key +  '0' * (BLKSZ - (len(key)))
    assert(len(key) == BLKSZ)

    key_array = [ 
        [ ord(i) for i in key[i:i+WORDSZ] ] \
            for i in xrange(0,len(key),WORDSZ)
    ]

    keywords = [None for i in xrange(wordn)]
    for i in xrange(WORDSZ):
        keywords[i] = key_array[i]

    # round constant, 3 right most bytes are always 0
    rcon = 0x1
    for i in xrange(WORDSZ,wordn):
        if i % WORDSZ == 0:
            x, rcon = g(keywords[i-1],rcon)
            keywords[i] = xor_lists( keywords[i-WORDSZ], x)
        else:
            keywords[i] = xor_lists( keywords[i-WORDSZ], keywords[i-1])

    return keywords

def test_keyschedule():
    logging.debug("testing keyschedules")
    keywords = keyschedule("hello",128)
    assert(keywords[0] == [104,101,108,108] )
    assert(keywords[4] == [109,97,104,104] )
    assert(keywords[21] == [226, 220, 98, 184] )
    assert(keywords[32] == [15, 49, 30, 44] )

def add_roundkey(state,rk):
    nstate = []
    for r1,r2 in zip(state,rk):
        nstate.append( xor_lists(r1,r2) )
    return nstate

def subbytes(state,inverse=False):
    global g_sbox
    global g_isbox
    box = g_isbox if inverse else g_sbox
    for i in xrange(len(state)):
        for j in xrange(len(state[0])):
            state[i][j] = box[ state[i][j] ]

    return state

# left = encrypt
# right = decrypt
def shiftrows(state,inverse=False):
    shift = shift_rows_right if inverse else shift_rows_left
    return shift(state)

def mixcolumns(state,inverse=False):
    m1 = ICOL_MATRIX if inverse else COL_MATRIX
    return matrix_multi(state, m1)

def matrix_to_bytes(matrix):
    r = ""
    for i in xrange(WORDSZ):
        for j in xrange(WORDSZ):
            r += chr( matrix[j][i] )
    return r

# input data is filed in by column, not by row; some online sources get this wrong
def create_roundkeys(keywords):
    roundkeys = []
    i = 0
    grps = [ keywords[i:i+WORDSZ] for i in xrange(0,len(keywords),WORDSZ) ]
    for grp in grps:
        key = [ [ 0 for _ in xrange(WORDSZ)] for _ in xrange(WORDSZ) ]
        for j in xrange(WORDSZ):
            for k in xrange(WORDSZ):
                key[k][j] = grp[j][k]
        roundkeys.append( key )
    return roundkeys

# lets do 128 for now

# encrypt
# substitue bytes
# shift rows
# mix columns
# add round key
# last round, no mix columns
def aes128_encrypt_block(key,plaintext_block):
    keywords = keyschedule(key,128)
    roundkeys = create_roundkeys(keywords)

    state = [ [ 0 for i in xrange(WORDSZ) ] for i in xrange(WORDSZ)]
    
    c = 0
    for i in xrange(WORDSZ):
        for j in xrange(WORDSZ):
            state[j][i] = ord(plaintext_block[c])
            c += 1

    state = add_roundkey(state,roundkeys[0])
    rci = 1
    for i in xrange(AES_128_ROUNDS):
        state = subbytes(state)
        state = shiftrows(state)
        state = mixcolumns(state)
        state = add_roundkey(state,roundkeys[rci])
        rci += 1
    
    # final round
    state = subbytes(state)
    state = shiftrows(state)
    state = add_roundkey(state,roundkeys[rci])

    ciphertext_block = matrix_to_bytes(state)
    return ciphertext_block

# decrypt
# keyschedule gen in reverse
# inverse shift rows
# inverse sub bytes
# add round key
# inverse mix columns
# last round, no mix columns
def aes128_decrypt_block(key,ciphertext_block):
    # probably don't need to calculate this everytime
    keywords = keyschedule(key,128)
    roundkeys = create_roundkeys(keywords)[::-1]
    state = [ [ 0 for i in xrange(WORDSZ) ] for i in xrange(WORDSZ)]

    c = 0
    for i in xrange(WORDSZ):
        for j in xrange(WORDSZ):
            state[j][i] = ord(ciphertext_block[c])
            c += 1

    state = add_roundkey(state, roundkeys[0])
    rci = 1
    for i in xrange(AES_128_ROUNDS):
        state = shiftrows(state,inverse=True)
        state = subbytes(state,inverse=True)
        state = add_roundkey(state, roundkeys[rci])
        state = mixcolumns(state,inverse=True)
        rci +=1

    # final round
    state = subbytes(state,inverse=True)
    state = shiftrows(state,inverse=True)
    state = add_roundkey(state,roundkeys[rci])

    plaintext_block = matrix_to_bytes(state)
    return plaintext_block

def test_aes_blocks():
    import hashlib

    logging.debug("testing aes blocks")
    # k ,m , e
    tests_128 = [
        # openssl enc -aes-128-ecb -in intext -k hello -nosalt -nopad -md md5
        (
            hashlib.md5("hello").digest(),
            "YELLOW SUBMARINE",
            "afcc5e0f85b858409ce061a5e987a0c8"
        ),
        (
            "Thats my Kung Fu", 
            "Two One Nine Two",
            "29C3505F571420F6402299B31A02D73A"
        ),
    ]

    for k,m,e in tests_128:
        x = aes128_encrypt_block(k,m)
        hx = binascii.hexlify(x)
        logging.debug('result: {}'.format(hx))
        logging.debug('expect: {}'.format(e))
        assert( e.lower() == hx.lower() )
        p = aes128_decrypt_block(k, x)
        assert( p == m )

def test_aes_ops():
    import hashlib
    logging.debug("testing full aes ecb ops")
    msg ='M2xDex5nfA60ltICqyGwoWo0D0f5jcen765RsZiGA3EhnnXW3zZnS3VJCrSbK6w1wJ2fPA9FUPzHSVKP'
    k = hashlib.md5('hello').digest()
    expect = ""
    expect += "787dda23c192a7e8a92b280187e02fdaed90bbb1fd7637e544d81a45b3b2fe7caaa8b4a66c4b"
    expect += "4b219d405f3ea277366203d92bf7f85cfaf5ab9138116c5fdc917a31e487cddcf3fa84a29241"
    expect += "0b25927e"

    ct = aes128_ecb_encrypt(k,msg)
    cth = binascii.hexlify(ct)
    logging.debug("cth: {}".format(cth))
    logging.debug("ex: {}".format(expect))
    assert(cth == expect)

    sanity = aes128_ecb_decrypt(k,ct)
    assert(sanity == msg)

def aes128_ecb_encrypt(k,msg):
    init_global_sbox()
    ciphertext = ""
    msgblks = [ msg[i:i+BLKSZ] for i in xrange(0,len(msg),BLKSZ) ]
    for m in msgblks:
        ciphertext += aes128_encrypt_block(k,m)
    return ciphertext

def aes128_ecb_decrypt(k,ciphertext):
    init_global_sbox()
    plaintext = ""
    cipherblks = [ ciphertext[i:i+BLKSZ] for i in xrange(0,len(ciphertext),BLKSZ) ]
    for c in cipherblks:
        plaintext += aes128_decrypt_block(k,c)
    return plaintext

if __name__ == "__main__":
    import logging
    logging.basicConfig(
            format="[%(asctime)s][%(levelname)s][%(funcName)s:%(lineno)d] %(msg)s",
            level=logging.DEBUG
            )

    init_global_sbox()

    test_gf()
    test_xor_lists()
    test_shift_row()
    test_matrix_multi()
    test_keyschedule()
    test_aes_blocks()
    test_aes_ops()
