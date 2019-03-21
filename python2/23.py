
from lib.challenge21 import MersenneTwister
from lib.challenge23 import reverse_mersenne


rng = MersenneTwister(seed=1337)
MT = []
print "reversing seed state of RNG"
for x in xrange(624):
    x = rng.extract_number()
    MT.append(reverse_mersenne( x))

print "cloning RNG state"
rng2 = MersenneTwister(seed=0)
rng2.MT = MT
print "compared clone RNG to OG RNG"
for i in xrange(12):
    print "rng1: ",rng.extract_number()
    print "rng2: ",rng2.extract_number()
    print ""
