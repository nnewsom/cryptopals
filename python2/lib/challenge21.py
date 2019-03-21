import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class MersenneTwister(object):
    def __init__(self,seed,bits=32):
        assert bits in [32,64]
        self.arch = bits
        if self.arch == 32:
            self.constants = {
                'w': 32,
                'n': 624,
                'm': 397,
                'r': 31,
                'u': 11,
                'd': 0xFFFFFFFF,
                's': 7,
                'b': 0x9D2C5680,
                't': 15,
                'c': 0xEFC60000,
                'l': 18,
                'f': 1812433253,
                'a': 0x9908B0DF
            }

        elif self.arch == 64:
            self.constants = {
                'w': 64,
                'n': 312,
                'm': 156,
                'r': 31,
                'u': 29,
                'd': 0x5555555555555555,
                's': 17,
                'b': 0x71D67FFFEDA60000,
                't': 37,
                'c': 0xFFF7EEE000000000,
                'l': 43,
                'f': 6364136223846793005,
                'a': 0xB5026F5AA96619E9
            }

        self.index = self.constants['n']+1
        self.lower_mask = (1 << self.constants['r']) - 1
        self.w_mask = 0xFFFFFFFF if bits == 32 else 0xFFFFFFFFFFFFFFFF

        if self.arch == 32:
            self.upper_mask = ~(self.lower_mask) & self.w_mask
        elif self.arch == 64:
            self.upper_mask =  ~(self.lower_mask) & self.w_mask

        debugstr = ""
        for k,v in self.constants.items():
            debugstr += "{k}: {v}, ".format(k=k,v=hex(v))
        logging.debug("arch: {a}\tupper_mask: {u}\tlower_mask: {l}".format(a=self.arch,u=hex(self.upper_mask),l=hex(self.lower_mask)))
        logging.debug(debugstr)

        self.MT = [ 0 for _ in xrange(self.constants['n']) ]
        self.__seed_MT(seed)

    def __seed_MT(self,seed):
        self.index = self.constants['n']
        self.MT[0] = seed
        for i in xrange(1,self.constants['n']):
            self.MT[i] = self.constants['f'] * (self.MT[i-1] ^ (self.MT[i-1] >> (self.constants['w']-2))) +i 
            self.MT[i] &= self.w_mask

    def __twist(self):
        for i in xrange(0,self.constants['n']):
            x = (self.MT[i] & self.upper_mask) + (self.MT[(i+1) % self.constants['n']] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.constants['a']
            self.MT[i] = self.MT[(i+self.constants['m']) % self.constants['n']] ^ xA
        self.index=0

    def extract_number(self):
        if self.index >= self.constants['n']:
            self.__twist()

        y = self.MT[self.index]
        
        y ^= (y >> self.constants['u']) & self.constants['d']
        y ^= (y << self.constants['s']) & self.constants['b']
        y ^= (y << self.constants['t']) & self.constants['c']
        y ^= (y >> self.constants['l'])
        self.index += 1

        return y & self.w_mask
            
