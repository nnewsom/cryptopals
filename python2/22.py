from lib.challenge21 import MersenneTwister
from random import randint
import time

t = int(time.time()) + randint(40,1000)
rng1 = MersenneTwister(seed = t)
x = rng1.extract_number()
print 'seed: {t}\tfirst value: {x}'.format(x=x,t=t)

t += randint(40,1000)
for i in xrange(0,2000):
    k = t - i
    rng2 = MersenneTwister(seed=k)
    y = rng2.extract_number()
    if x == y:
        print "found seed: {k}".format(k=k)
        break
