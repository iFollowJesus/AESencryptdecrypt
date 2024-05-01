import random
from Sbox import SBox 

        #self.key_lengths = [128, 192, 256]
       # if key_length is None:
        #    key_length = random.choice(self.key_lengths)
       # self.gen_key(key_length)

class AES:
    def __init__(self, key_length=None):
        
        key_length = 16  # Set the key length (in bytes)
        key = self.generate_key(key_length)
        print("The original key! ", key)
        roundkeys, key_matrix = self.keySchedule(key)


    # AES Round Constants for key schedule
    round_constants = {
        0: 0x00,
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


    def generate_key(self, key_length):
        
        return [random.randint(0, 255) for _ in range(key_length)]

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

        while not self.get_block(block, char_array, index):
            out_text.append(self.cipher_block(block, mode))
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

        num_rounds = len(self.key) // 4 + 5

        for _ in range(num_rounds):
            self.sub_bytes(block, mode)
            self.shift_rows(block)
            # Assuming MixColumns is a required step but left as a placeholder
            # self.mix_columns(block)
            self.add_round_key(block)

        self.sub_bytes(block, mode)
        self.shift_rows(block)
        self.add_round_key(block)

        cipher_block = ''
        for col in range(4):
            for row in range(4):
                cipher_block += block[row][col]

        return cipher_block
    
    def keySchedule(self, key):
        final_keys = []
        print("This is the key ", key)
        first_third_words = [None, None, None]
        N = len(key)
        if N == 16:
            num_rounds = 10
        elif N == 24:
            num_rounds = 12
        elif N == 32:
            num_rounds = 14

        # Convert the original key into a 2D array
        initial_numbers = [key[i:i+4] for i in range(0, len(key), 4)]
        print("These are the inital numbers ", initial_numbers)

        final_keys.append(initial_numbers)

        round_keys = self.generate_round_key(initial_numbers, 0)

        final_keys.append(round_keys)

        print("All keys intial", final_keys)

        for i in range(1, num_rounds + 1):
            # Generate the next round key
            print("The round keys: ", round_keys)
            round_keys = self.generate_round_key(round_keys, i) 
            final_keys.append(round_keys)
        
        print("All keys", final_keys)

    # Check the length of round_keys
        print("Total number of round keys:", len(round_keys))

        return round_keys, initial_numbers


    def generate_round_key(self, key, round_num):
            prev_round_key = key.copy() 
            print("prev_round key", prev_round_key)
            last_num = [word for word in prev_round_key[-1]]
            print("last num," ,last_num)
            new_key_word = self.generate_round_key_word(last_num, round_num)
            new_round_key = self.generate_new_round_keys(prev_round_key, new_key_word)
            return new_round_key


    def generate_new_round_keys(self, prev_round_key, new_key_word):

        new_key_word_int = [int(new_key_word[i:i+2], 16) for i in range(2, len(new_key_word), 2)]

        print("new_key_word_int ", new_key_word_int)

        # Perform XOR on the first word
        xor_result = [prev_round_key[0][i] ^ new_key_word_int[i] for i in range(len(prev_round_key[0]))]


        # Will hold all the new round keys 
        new_round_keys = [xor_result]

        # Peform XOR on the second through 4th word
        for word in prev_round_key[1:]:
            xor_result = [xor_result[i] ^ word[i] for i in range(len(word))]

            new_round_keys.append(xor_result)

        return new_round_keys



    def generate_round_key_word(self, last_num, round_constant):
        
        # Rotate the numbers
        rotated_num = last_num[1:] + [last_num[0]]
        print("After the num rotated ", rotated_num)
        
        # Convert the rotated numbers to bytes
        byte_values = [num.to_bytes(1, 'big') for num in rotated_num]

        word_hex = ""  
        for byte in byte_values:

            bits = bin(int.from_bytes(byte, 'big'))[2:].zfill(8)

            row_bits = bits[:4]
            column_bits = bits[4:]

            row_hex = hex(int(row_bits, 2))
            column_hex = hex(int(column_bits, 2))

            # Perform substitution using S-box
            sub_byte_result = self.sub_bytes(row_hex, column_hex, mode=True)
            
            # Convert to hexadecimal
            sub_byte_result_hex = hex(sub_byte_result)[2:].zfill(2)
            word_hex += sub_byte_result_hex

        # Convert to integer
        word_hex_value = int(word_hex, 16)

        round_constant = self.round_constants[round_constant]
        word_hex_value ^= round_constant
        # Concat each hexadecimal from the sbox into one
        final_value = hex(word_hex_value)

        return final_value


    
    def sub_bytes(self, row_hex, column_hex, mode):
        result = None
        if mode:
            result = SBox.eSBox[int(row_hex,16)][int(column_hex,16)]
        else:
            result = SBox.dSBox[int(row_hex,16)][int(column_hex,16)]
        return result



    def shift_rows(self, block):
        for r in range(1, 4):
            row = block[r]
            block[r] = row[r:] + row[:r]

    # Placeholder for MixColumns operation
    def mix_columns(self, block):
        pass

    # For displaying the block
    def print_block(self, block):
        for r in range(4):
            print(' '.join(str(ord(c)) for c in block[r]))

    def getKeyWord():
        word = {}
        

# Example usage
if __name__ == '__main__':
    #plain_text = "The quick brown fox jumps over the lazy dog.  Lorem ipsum dolor sit amet."

    rijndael = AES()
    #cipher_text = rijndael.encrypt(plain_text)
    #print(cipher_text)

    #decrypt_text = rijndael.decrypt(cipher_text)
    #print(decrypt_text)
