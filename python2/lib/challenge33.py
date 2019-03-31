# def modexp(base,exp,mod):
#     r = 1
#     for _ in xrange(exp):
#         r = (r * base) % mod
#     return r

# this is sooooo much faster computationally;  not even funny
def modexp(base,exp,mod):
    return pow(base,exp,mod)

if __name__ == "__main__":
    r1 = pow(4,13) % 497
    r2 = modexp(4,13,497)
    print ("r1: {r1}\tr2: {r2}".format(r1=r1,r2=r2))
    assert( pow(4,13) % 497  == modexp(4,13,497) )
