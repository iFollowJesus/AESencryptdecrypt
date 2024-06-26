import random
from Sbox import SBox
from mixColumns import mixColumns

class AES:
    def __init__(self, key_length=None):
        self.key_lengths = [128, 192, 256]
        if key_length is None:
            key_length = random.choice(self.key_lengths)
        self.gen_key(key_length)

    # AES Round Constants for key schedule
    round_constants = {
        1: 0x01,
        2: 0x02,
        3: 0x04,
        4: 0x08,
        5: 0x10,
        6: 0x20,
        7: 0x40,
        8: 0x80,
        9: 0x1B,
        10: 0x36
    }


    def gen_key(self, key_length):
        self.key = [self.rand_byte() for _ in range(key_length // 8)]

    def rand_byte(self):
        return random.randint(0, 255)

    def encrypt(self, plaintext):
        return self.cipher(plaintext, True)

    def decrypt(self, ciphertext):
        return self.cipher(ciphertext, False)

    def cipher(self, in_text, mode):
        char_array = list(in_text)
        block = [[None for _ in range(4)] for _ in range(4)]
        out_text = []
        index = 0

        while index < len(char_array):
            last_block = self.get_block(block, char_array, index)
            out_text.append(self.cipher_block(block, mode))
            if last_block:
                break
            index += 16

        return ''.join(out_text)

    def get_block(self, block, chars, index):
        last_block = False
        for col in range(4):
            for row in range(4):
                if index >= len(chars):
                    block[row][col] = chr(self.rand_byte())
                    last_block = True
                else:
                    block[row][col] = chars[index]
                    index += 1
        return last_block

    def cipher_block(self, block, mode):
        self.add_round_key(block)

        num_rounds = 10 if len(self.key) == 16 else (12 if len(self.key) == 24 else 14)

        for _ in range(num_rounds):
            self.sub_bytes(block, mode)
            self.shift_rows(block)
            if mode:
                mixColumns.mix_columns(block)  # Use the mixColumns function for encryption
            else:
                mixColumns.inv_mix_columns(block)  # Use the invMixColumns function for decryption
            self.add_round_key(block)

        self.sub_bytes(block, mode)
        self.shift_rows(block)
        self.add_round_key(block)

        cipher_block = ''
        for col in range(4):
            for row in range(4):
                cipher_block += block[row][col]

        return cipher_block

    def add_round_key(self, block):
        pass  # Placeholder for the AddRoundKey operation

    def sub_bytes(self, block, mode):
        for r in range(4):
            for c in range(4):
                if mode:
                    block[r][c] = chr(SBox.encrypt(ord(block[r][c])))
                else:
                    block[r][c] = chr(SBox.decrypt(ord(block[r][c])))

    def shift_rows(self, block):
         for r in range(1, 4):
            row = block[r]
            if r == 1:
                block[r] = row[r:] + row[:r]  # shift left for encryption
            elif r == 2:
                block[r] = row[r:] + row[:r]  # shift left twice or right twice
            elif r == 3:
                block[r] = row[-r:] + row[:-r]  # shift right for decryption

    # Placeholder for MixColumns operation
    def mix_columns(self, block):
        pass

    # For displaying the block
    def print_block(self, block):
        for r in range(4):
            print(' '.join(str(ord(c)) for c in block[r]))

    def keySchedule(key):
        N = len(key)

    def getKeyWord():
        word = {}
        

# Example usage
if __name__ == '__main__':
    plain_text = "The quick brown fox jumps over the lazy dog.  Lorem ipsum dolor sit amet."

    rijndael = AES()
    cipher_text = rijndael.encrypt(plain_text)
    print(cipher_text)

    decrypt_text = rijndael.decrypt(cipher_text)
    print(decrypt_text)
