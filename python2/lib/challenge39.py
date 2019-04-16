import random
import logging

from challenge33 import modexp

def fermat_test(n):
    # if its even, why bother?
    if n <= 3 or n % 2 == 0:
        return False

    a = random.randint(2,n-2)
    r = modexp(a,n-1,n)
    if r != 1:
        return False

    return True

def miller_rabin_test(n):
    # if its even, why bother?
    if n % 2== 0:
        return False

    if n in [ 2,3,5,7,11,13,17]:
        return True

    # n - 1 = 2^s * d
    s = 0
    d = n-1
    while d % 2 == 0:
        d >>= 1
        s +=1

#     logging.debug("n: {n}".format(n=n))
#     logging.debug("d: {d}".format(d=d))
#     logging.debug("s: {s}".format(s=s))

    a = random.randrange(2, n - 2)
    x = modexp(a, d, n) 
    # needs to be +1, or -1 for first gen
    if x in [ 1, n-1 ]:
        return True

    for i in xrange(s):
        x = modexp(x, 2, n)
        if x == 1:
            return False
        # needs to be -1 for rest of tests
        elif x == n-1:
            return True

    return False

def is_prime(n,k=10):
    for _ in xrange(k):
        if not fermat_test(n) or not miller_rabin_test(n):
            return False
    return True
        
def seek_prime(start=1,end=1000,k=10):
    for p in xrange(start,end):
        if is_prime(p,k):
            return p
    return None

def gen_seq_prime(start=0,bitlength=8,k=10):
    n = start if start else pow(2,bitlength)
    while True:
        n +=1
        if is_prime(n,k):
            return n

def gen_rand_prime(start=100,end=500,up_range=100):
    ss = random.randint(start,end)
    num_tries = 3
    p = 0
    for _ in xrange(num_tries):
        p = seek_prime(ss,ss+up_range)
        ss += up_range
        if p:
            break

    return p

def extended_euclidean(a,b):
    x0 = 0
    x1 = 1 # old s

    y0 = 1
    y1 = 0 # old t

    r0 = b
    r1 = a # old r

    q = 0 

    while r0 != 0:
        q = r1 / r0
        (r1, r0) = ( r0, r1 - q * r0 )
        (y1, y0) = ( y0, y1 - q * y0 )
        (x1, x0) = ( x0, x1 - q * x0 )

    # logging.debug("bezout: {s}".format(s = (x1,y1)) )
    # logging.debug("gcd: {s}".format(s = r1) )
    # logging.debug("quotients: {s}".format(s = (y0,x0)) )
    # assert gcd = ax + by
    assert( r1  == a * x1 + b * y1 )

    # logging.debug("return: {s}".format(s=( r1, x1, y1 )))
    # returning (gcd, x, y )
    return ( r1, x1, y1 )

def inverse_modulo(a,b):
    g, x, y = extended_euclidean(a,b)
    # must be coprime
    assert( g == 1)
    if x < 0:
        x = b + x
    # make sure eq still holds
    assert( (a*x) % b + (y*b) % b == g )
    # (y * b) % b == 0
    assert( (a*x) % b == g )

    return x

def generate_seq_rsa_keypairs(bitlength=1024,e=3):
    """deeeeeefinately not secure prime selection. just for test purposes"""
    p = gen_seq_prime(bitlength=bitlength)
    q = 0
    while True:
        q = gen_seq_prime(start = q+1 if q else p +1)
        n = p * q
        et = ( p-1 ) * ( q-1 ) # totient
        e = e
        try:
            d = inverse_modulo(e,et)
            logging.debug("p: {p}".format(p=p))
            logging.debug("q: {q}".format(q=q))
            logging.debug("totient: {et}".format(et=et))
            break
        except AssertionError:
            # et is not coprime
            continue

    pub_key = [ e, n ]
    priv_key = [ d, n ]
    return pub_key, priv_key

def generate_rsa_keypairs(prange,e=3):
    start,end = prange
    while True:
        p = gen_rand_prime(start,end)
        q = gen_rand_prime(start,end)

        n = p * q
        et = ( p-1 ) * ( q-1 ) # totient
        e = 3
        try:
            d = inverse_modulo(e,et)
            break
        except AssertionError:
            # et is not coprime
            continue

    pub_key = [ e, n ]
    priv_key = [ d, n ]
    return pub_key, priv_key

def simple_rsa(m,keypair):
    k,n = keypair
    return modexp(m,k,n)

def test_fermat_gen():
    # https://primes.utm.edu/lists/small/10000.txt
    first_primes_2k = [
        5,7,11,13,17,19,23,29,
        31,37,41,43,47,53,59,61,67,71,
        73,79,83,89,97,101,103,107,109,113,
        127,131,137,139,149,151,157,163,167,173,
        179,181,191,193,197,199,211,223,227,229,
        233,239,241,251,257,263,269,271,277,281,
        283,293,307,311,313,317,331,337,347,349,
        353,359,367,373,379,383,389,397,401,409,
        419,421,431,433,439,443,449,457,461,463,
        467,479,487,491,499,503,509,521,523,541,
        547,557,563,569,571,577,587,593,599,601,
        607,613,617,619,631,641,643,647,653,659,
        661,673,677,683,691,701,709,719,727,733,
        739,743,751,757,761,769,773,787,797,809,
        811,821,823,827,829,839,853,857,859,863,
        877,881,883,887,907,911,919,929,937,941,
        947,953,967,971,977,983,991,997,1009,1013,
        1019,1021,1031,1033,1039,1049,1051,1061,1063,1069,
        1087,1091,1093,1097,1103,1109,1117,1123,1129,1151,
        1153,1163,1171,1181,1187,1193,1201,1213,1217,1223,
        1229,1231,1237,1249,1259,1277,1279,1283,1289,1291,
        1297,1301,1303,1307,1319,1321,1327,1361,1367,1373,
        1381,1399,1409,1423,1427,1429,1433,1439,1447,1451,
        1453,1459,1471,1481,1483,1487,1489,1493,1499,1511,
        1523,1531,1543,1549,1553,1559,1567,1571,1579,1583,
        1597,1601,1607,1609,1613,1619,1621,1627,1637,1657,
        1663,1667,1669,1693,1697,1699,1709,1721,1723,1733,
        1741,1747,1753,1759,1777,1783,1787,1789,1801,1811,
        1823,1831,1847,1861,1867,1871,1873,1877,1879,1889,
        1901,1907,1913,1931,1933,1949,1951,1973,1979,1987,
        1993,1997,1999
    ]
    start = 3
    index = 0
    # quick sanity test
    logging.debug("testing miller rabin")
    assert(miller_rabin_test(53) == True)
    logging.debug("testing fermat")
    assert(fermat_test(53) == True)

    logging.debug("verifying first primes under 2k")
    for i,pv in enumerate(first_primes_2k):
        #logging.debug("start: {s} next prime: {p}".format(s=start,p=pv))
        p = seek_prime(start=start,end=2008,k=10)
        #logging.debug("prime found: {p}".format(p=p))
        assert(p == pv)
        start = p+1

    r = gen_rand_prime(100,200)
    logging.debug("random gen prime: {r}".format(r=r))
    assert(r in first_primes_2k)

    r = gen_rand_prime(500,700)
    logging.debug("random gen prime: {r}".format(r=r))
    assert(r in first_primes_2k)

def test_inverse_modulo():
    x =inverse_modulo(17,3120)
    logging.debug("inverse modulo (17,3120) = {x}".format(x = x ))
    assert(x == 2753)

def test_gen_seq_prime():
    p = gen_seq_prime(bitlength=32)
    logging.debug(p)
    p = gen_seq_prime(bitlength=64)
    logging.debug(p)
    p = gen_seq_prime(bitlength=128)
    logging.debug(p)
    p = gen_seq_prime(bitlength=256) 
    logging.debug(p)
    p = gen_seq_prime(bitlength=512) 
    logging.debug(p)
    p = gen_seq_prime(bitlength=1024) 
    logging.debug(p)
    p,pv = generate_seq_rsa_keypairs(bitlength=1024)
    logging.debug(p)
    logging.debug(pv)

if __name__ == "__main__":
    import logging
    logging.basicConfig(
            format="[%(asctime)s][%(levelname)s][%(funcName)s:%(lineno)d] %(msg)s",
            level=logging.DEBUG
            )
    test_fermat_gen()
    test_inverse_modulo()
    test_gen_seq_prime()
