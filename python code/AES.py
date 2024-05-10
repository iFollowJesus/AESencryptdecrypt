import random
from Sbox import SBox
from mixColumns import mixColumns

class AES:
    def __init__(self, key_length=16):
        self.mix_columns_instance = mixColumns()
        key = self.generate_key(key_length)
        print("The original key! ", key)
        # Assuming the key_schedule method returns only the final_round_keys
        self.final_round_keys = self.key_schedule(key)

        print("THE FINAL KEYS", self.final_round_keys)


    # AES Round Constants for key schedule
    def get_round_constants(self, round_num):
        round_constants = [
            [0x01, 0x00, 0x00, 0x00],
            [0x02, 0x00, 0x00, 0x00],
            [0x04, 0x00, 0x00, 0x00],
            [0x08, 0x00, 0x00, 0x00],
            [0x10, 0x00, 0x00, 0x00],
            [0x20, 0x00, 0x00, 0x00],
            [0x40, 0x00, 0x00, 0x00],
            [0x80, 0x00, 0x00, 0x00],
            [0x1B, 0x00, 0x00, 0x00],
            [0x36, 0x00, 0x00, 0x00],
            [0x6C, 0x00, 0x00, 0x00],  # For AES-192 (12 rounds)
            [0xD8, 0x00, 0x00, 0x00],  # For AES-192 (12 rounds) and AES-256 (14 rounds)
            [0xAB, 0x00, 0x00, 0x00],  # For AES-256 (14 rounds)
            [0x4D, 0x00, 0x00, 0x00],  # For AES-256 (14 rounds)
        ]

        round_constant = round_constants[round_num]

        return round_constant


    def generate_key(self, key_length):
        
        return [random.randint(0, 255) for _ in range(key_length)]

    def rand_byte(self):
        return random.randint(0, 255)

    def encrypt(self, plaintext_bytes):
        plaintext_padded = self.pad_plaintext(plaintext_bytes)
        print("Real plaintext after padding? ")
        print(plaintext_padded)
        ciphertext = bytearray()
        for i in range(0, len(plaintext_padded), 16):
            block = plaintext_padded[i:i+16]
            print("Plaintext block after padding")
            print(block)
            encrypted_block = self.cipher_block(block, mode=True)
            ciphertext.extend(encrypted_block)
        return bytes(ciphertext)


    def decrypt(self, ciphertext_bytes):
        decipheredText = bytearray()
        for i in range(0, len(ciphertext_bytes), 16):
            block = ciphertext_bytes[i:i+16]
            decrypted_block = self.cipher_block(block, mode=False)
            print("Decrypted_block", decrypted_block)  # Add this line to print the decrypted block
            decipheredText.extend(decrypted_block)

        print("Deciphered Text before trying to remove padding", decipheredText)
        # Remove padding
        deciphered_text = self.unpad_plaintext(decipheredText)

        print("Unpadded text: ", deciphered_text)

        # Decode the plaintext
        try:
            plaintext_decoded = deciphered_text.decode("utf-8")
            print("Decoded text:", plaintext_decoded)
        except UnicodeDecodeError:
            print("Unable to decode decrypted bytes as UTF-8. Trying to replace invalid sequences...")
            plaintext_decoded = deciphered_text.decode("utf-8", errors="replace")
            print("Decoded text (UTF-8, with invalid sequences replaced):", plaintext_decoded)

        return deciphered_text

    def add_round_key(self, block, round_key):
        for i in range(4):  # Iterate over columns
            for j in range(4):  # Iterate over rows
                block[j][i] ^= round_key[i][j]  # Perform XOR operation


    def key_schedule(self, key):
        key_bytes = [b for b in key] 
        key_length = len(key_bytes)

        if key_length == 16:
            nr = 10  # Number of rounds (10 for 128-bit keys)
        elif key_length == 24:
            nr = 12  # Number of rounds (12 for 192-bit keys)
        elif key_length == 32:
            nr = 14  # Number of rounds (14 for 256-bit keys)
        else:
            raise ValueError("Invalid key length")

        round_keys = [key_bytes[i:i+4] for i in range(0, len(key_bytes), 4)]  # Split key into 32-bit words
        final_round_keys = []

        for i in range(nr + 1):  
            if i == 0:
                final_round_keys.append(round_keys.copy())
                print("initial final round keys", final_round_keys)
            else:
                new_round_key = self.generate_round_key(final_round_keys[-1], i - 1) 
                final_round_keys.append(new_round_key)

        return final_round_keys


    def generate_round_key(self, key, round_num):
            print("The round key number is:", round_num)
            prev_round_key = key.copy() 
            print("The previous round key", prev_round_key)
            
            last_num = [word for word in prev_round_key[-1]]
            print("The last word is ", last_num)
            new_key_word = self.generate_round_key_word(last_num, round_num)
            new_round_key = self.generate_new_round_keys(prev_round_key, new_key_word)
            return new_round_key
            
    def generate_round_key_word(self, last_num, round_num):
        # Rotate the numbers
        rotated_num = last_num[1:] + [last_num[0]]
        print("The rotated num", rotated_num)

        transformed_bytes = []

        for byte in rotated_num:

            # Perform substitution using S-box
            substituted_byte = self.sub_bytes(byte, mode=True)
            
            transformed_bytes.append(substituted_byte)

        print("The substituted result was", transformed_bytes)
        round_constants = self.get_round_constants(round_num)
        print("The round constants are ", round_constants)
        xor_result = bytes([b1 ^ b2 for b1, b2 in zip(transformed_bytes, round_constants)])
        print("XORed Result:")
        xor_list = [integer for integer in xor_result]
        print("The XOR list", xor_list)
        return xor_list

    
    def generate_new_round_keys(self, prev_round_key, new_key_word):

        print("The previous round key is: ", prev_round_key)
        new_round_keys = []

        for sub_key in prev_round_key:
                # XOR the new key word with each integer in the current list
                xor_result = [b1 ^ b2 for b1, b2 in zip(sub_key, new_key_word)]
                new_round_keys.append(xor_result)
        print("The new round keys are: ", new_round_keys)

        return new_round_keys

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

    def sub_bytes(self, pByte, mode):
        result = None
        if mode:
            result = SBox.encrypt(pByte)
        else:
            result = SBox.decrypt(pByte)
        return result

    def shift_rows(self, block):
        for r in range(1, 4):
            row = block[r]
            block[r] = row[r:] + row[:r]

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



