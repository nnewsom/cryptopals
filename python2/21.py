from lib.challenge21 import MersenneTwister
import random

rng = MersenneTwister(seed=0)
print rng.extract_number()
