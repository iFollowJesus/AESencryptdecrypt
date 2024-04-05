import random

class AES:
    def __init__(self, keyLength=None):
        self.keyLengths = [128, 192, 256]
        if keyLength is None:
            keyLength = random.choice(self.keyLengths)
        self.genKey(keyLength)

    def genKey(self, keyLength):
        self.key = [0] * (keyLength // 8)
        for i in range(len(self.key)):
            self.key[i] = self.randByte()

    def randByte(self):
        return int(random.random() * 256)

    def getRandomLength(self):
        return random.choice(self.keyLengths)
    
    # More methods to be implemented as needed
