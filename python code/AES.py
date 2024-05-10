import random
from Sbox import SBox
from mixColumns import mixColumns

class AES:
    def __init__(self, key_length=16):
        self.mix_columns_instance = mixColumns()
        self.key = self.generate_key(key_length)
        self.key = [84, 104, 97, 116, 115, 32, 109, 121, 32, 75, 117, 110, 103, 32, 70, 117]
        print("The original key! ", self.key)
        
        self.final_round_keys = self.key_schedule(self.key)
        print("THE FINAL KEYS", self.final_round_keys)
        for key_list in self.final_round_keys:
            hex_keys = AES.int_list_to_hex(key_list)
            print(hex_keys)

    def int_list_to_hex(key_list):
        hex_keys = []
        for key_row in key_list:
            hex_row = []
            for num in key_row:
                hex_row.append(hex(num)[2:].zfill(2))
            hex_keys.append(hex_row)
        return hex_keys
    
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

    def bytes_to_state_matrix(self, block):
        state_matrix = [[0] * 4 for _ in range(4)]  # Initialize a 4x4 matrix with zeros

        for i, byte in enumerate(block):
            col = i % 4  # Determine the column index
            row = i // 4  # Determine the row index
            state_matrix[row][col] = byte

        return state_matrix
    
    def encrypt(self, plaintext):
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext = bytearray()
        for i in range(0, len(plaintext_bytes), 16):
            block = plaintext_bytes[i:i+16]
            print("Block to state matrix?", block)
            
            state_matrix = self.bytes_to_state_matrix(block)  # Convert block to state matrix

            print("State matrix for plaintext block:", state_matrix)
            encrypted_block = self.cipher_block(state_matrix, mode=True) 
            print("The final block!?!?", encrypted_block)
        return bytes(ciphertext)



    def decrypt(self, ciphertext_bytes):
        decipheredText = bytearray()
        for i in range(0, len(ciphertext_bytes), 16):
            block = ciphertext_bytes[i:i+16]
            decrypted_block = self.cipher_block(block, mode=False)
            print("Decrypted_block", decrypted_block) 
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

    def key_schedule(self, key):
        key_bytes = [b for b in key] 
        key_length = len(key_bytes)

        if key_length == 16:
            nr = 10 
        elif key_length == 24:
            nr = 12  
        elif key_length == 32:
            nr = 14  
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

        transformed_bytes = []

        for byte in rotated_num:

            # Perform substitution using S-box
            substituted_byte = self.sub_bytes(byte, mode=True)
            
            transformed_bytes.append(substituted_byte)

        round_constants = self.get_round_constants(round_num)
        xor_result = bytes([b1 ^ b2 for b1, b2 in zip(transformed_bytes, round_constants)])
        xor_list = [integer for integer in xor_result]
        return xor_list

    
    def generate_new_round_keys(self, prev_round_key, new_key_word):

        new_round_keys = []

        for sub_key in prev_round_key:
                # XOR the new key word with each integer in the current list
                xor_result = [b1 ^ b2 for b1, b2 in zip(sub_key, new_key_word)]
                new_round_keys.append(xor_result)
                new_key_word = xor_result

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
    
    def add_round_key(self, block, round_key):
        print("Block Im recieving from round key")
        self.print_block_hex(block)
        print("round key im reciving from round key")
        self.print_block_hex(round_key)
        for j in range(4):  # Iterate over rows
            for i in range(4):  # Iterate over columns
                block[j][i] ^= round_key[j][i]  # Perform XOR operation


    def print_block_hex(self, block):
        for i in range(4):  
            hex_column = " ".join(format(row[i], '02X') for row in block)
            print(hex_column)


    def transpose_block(self, block):
        
        block_transposed = [[block[j][i] for j in range(len(block))] for i in range(len(block[0]))]
        return block_transposed
    
    def transpose_to_columns(self, block):
        # Transpose the block matrix back to columns
        block_columns = [[block[j][i] for j in range(len(block))] for i in range(len(block[0]))]
        return block_columns
    
    def cipher_block(self, block, mode):

        num_rounds = 10 if len(self.key) == 16 else (12 if len(self.key) == 24 else 14)
        print("Number of rounds", num_rounds)

        for round_num in range(num_rounds):
            print("The round_num", round_num)
            round_key = self.final_round_keys[round_num]


           
            self.add_round_key(block, round_key)
            print("RoundKey thing ", self.print_block_hex(block))

            print("The round key bloc", round_num)
            print(self.print_block_hex(block))

            # Adding what came from sub bytes to the block
            new_block = []
            for row in block:  
                        new_row = []  
                        for byte in row:  
                            new_byte = self.sub_bytes(byte, mode)  
                            new_row.append(new_byte)  
                        new_block.append(new_row)  
            block = new_block  

            print(self.print_block_hex(block))

            transposed_block = self.transpose_block(block)

            self.shift_rows(transposed_block)
            print("Shifted rows")
            self.transpose_to_columns(transposed_block)
            self.transpose_to_columns(transposed_block)

            #Skip mixColumns for the final round
            if round_num == num_rounds - 1:
                finalBlock = self.transpose_block(transposed_block)
                self.add_round_key(finalBlock, self.final_round_keys[round_num + 1])
                print("FInal block")
                self.print_block_hex(finalBlock)
                cipher_block = ' '.join([''.join(format(byte, '02X') for byte in row) for row in finalBlock])
                break  

            # MixColumns
            if mode:
                block = mixColumns.mix_columns(transposed_block)
                block = self.transpose_to_columns(block)
                print("block columns from mix row")
                print(self.print_block_hex(block))
            else:
                mixColumns.inv_mix_columns(block)

        return cipher_block

    def sub_bytes(self, pByte, mode):
        result = None
        if mode:
            result = SBox.encrypt(pByte)
        else:
            result = SBox.decrypt(pByte)
        return result

    def shift_rows(self, block):
        for c in range(1, 4):  # Start from the second column (index 1) to the last column
            shift_amount = c  # Determine the number of positions to shift
            block[c] = block[c][shift_amount:] + block[c][:shift_amount]


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
    plain_text = "Two One Nine Two"

    rijndael = AES()
    cipher_text = rijndael.encrypt(plain_text)
    #print(cipher_text)

    #decrypt_text = rijndael.decrypt(cipher_text)
    #print(decrypt_text)