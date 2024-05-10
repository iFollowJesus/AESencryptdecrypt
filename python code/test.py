import random
from Sbox import SBox
from mixColumns import mixColumns

class AES:
    def __init__(self, key_length=None):
        self.key_lengths = [128, 192, 256]
        if key_length is None:
            key_length = random.choice(self.key_lengths)
        self.gen_key(key_length)
        self.mix_columns = mixColumns()  # Creating an instance of your mixColumns class

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
                    block[row][col] = chr(self.rand_byte())  # Padding random bytes if needed
                    last_block = True
                else:
                    block[row][col] = chars[index]
                    index += 1
        return last_block

    def cipher_block(self, block, mode):
        self.add_round_key(block)  # Placeholder for actual implementation

        num_rounds = 10 if len(self.key) == 16 else (12 if len(self.key) == 24 else 14)

        for round_num in range(num_rounds):
            self.sub_bytes(block, mode)
            self.shift_rows(block)
            if mode:
                self.mix_columns.mix_columns(block)  # Use the mixColumns function for encryption
            else:
                self.mix_columns.inv_mix_columns(block)  # Use the invMixColumns function for decryption
            self.add_round_key(block)

        self.sub_bytes(block, mode)
        self.shift_rows(block)
        self.add_round_key(block)

        return ''.join([''.join(row) for row in block])

    def add_round_key(self, block):
        # Placeholder - should XOR block with key scheduled for this round
        pass

    def sub_bytes(self, block, mode):
        for r in range(4):
            for c in range(4):
                if mode:  # Encrypt mode
                    block[r][c] = chr(SBox.encrypt(ord(block[r][c])))
                else:  # Decrypt mode
                    block[r][c] = chr(SBox.decrypt(ord(block[r][c])))

    def shift_rows(self, block):
        # Rotate rows left (encryption) or right (decryption)
        for r in range(1, 4):
            block[r] = block[r][r:] + block[r][:r] if mode else block[r][-r:] + block[r][:-r]

if __name__ == '__main__':
    plain_text = "The quick brown fox jumps over the lazy dog."
    aes = AES(key_length=128)  # Example with a 128-bit key
    cipher_text = aes.encrypt(plain_text)
    print("Encrypted:", cipher_text)

    decrypted_text = aes.decrypt(cipher_text)
    print("Decrypted:", decrypted_text)
