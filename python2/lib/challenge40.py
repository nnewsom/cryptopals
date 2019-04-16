from challenge39 import inverse_modulo, extended_euclidean
from challenge33 import modexp

import logging

def crt(cn1,cn2,cn3):
    c1, n1 = cn1
    c2, n2 = cn2
    c3, n3 = cn3

    gcd,x,y = extended_euclidean(n1,n2)
    if(gcd != 1):
        logging.error("gcd(n1,n2) != 1 ")
        return -1
    gcd,x,y = extended_euclidean(n1,n3)
    if(gcd != 1):
        logging.error("gcd(n1,n3) != 1 ")
        return -1
    gcd,x,y = extended_euclidean(n2,n3)
    if(gcd != 1):
        logging.error("gcd(n2,n3) != 1 ")
        return -1

    # section 1
    x1 = (n2 * n3) 
    logging.debug("x1: {x}".format(x=x1))
    z = inverse_modulo(x1,n1)
    logging.debug("x1,n1^-1 = {z}".format(z=z))
    s1 = c1 * x1 * inverse_modulo(x1,n1)
    logging.debug("s1: {s}".format(s=s1))

    # section 2
    x2 = (n1 * n3)
    logging.debug("x2: {x}".format(x=x2))
    z = inverse_modulo(x2,n2)
    logging.debug("x2,n2^-1 = {z}".format(z=z))
    s2 = c2 * x2 * z
    logging.debug("s2: {s}".format(s=s2))

    # section 3
    x3 = (n1 * n2)
    logging.debug("x3: {x}".format(x=x3))
    z = inverse_modulo(x3,n3)
    logging.debug("x3,n3^-1 = {z}".format(z=z))
    s3 = c3 * x3 * inverse_modulo(x3,n3)
    logging.debug("s3: {s}".format(s=s3))

    n = n1 * n2 * n3
    r = (s1 + s2 + s3) %  n
    
    return r, n 

# this method doesn't work for large rsa level ints
# def cube_root(n):
#     # just for small numbers
#     # need round(); otherwise 4.0 == 3 cause why not, right python?
#     x = int(round(pow(n, 1.0 /3.0)))
#     logging.debug("{fx} ({x})".format(
#                     fx = pow(n, 1.0 /3.0),
#                     x = x
#                 ))
#     if pow(x,3) != n:
#         logging.debug("{n} no cube root".format(n=n))
#         return -1
#     else:
#         logging.debug("{n} cube root {x}".format(n=n,x=x))
#         return x

def cube_root(n,near=False):
    result = 0
    l = 0
    r = n
    while l <= r:
        m  = ( l + r ) // 2
        if pow(m,3) < n:
            l = m + 1
        elif pow(m,3) > n:
            r = m - 1
        else:
            result = m
            break

    if not result and near:
        result = l

    return result

def test_crt():
    cn1 = (2,3)
    cn2 = (2,4)
    cn3 = (1,5)
    r,n = crt(cn1, cn2, cn3)
    assert( r == 26 and n == 60 )
    
    logging.debug("r: {r} n: {n}".format(r=r,n=n))

def test_cube_root():
    assert( cube_root(9) == 0 )
    assert( cube_root(8) ==  2 )
    assert( cube_root(64) ==  4 )

if __name__ == "__main__":
    import logging
    logging.basicConfig(
            format="[%(asctime)s][%(levelname)s][%(funcName)s:%(lineno)d] %(msg)s",
            level=logging.DEBUG
            )

    test_crt()
    test_cube_root()
