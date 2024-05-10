import random
from Sbox import SBox
from mixColumns import mixColumns

debug = False

class AES:
    def __init__(self, key_length=16):
        self.mix_columns_instance = mixColumns()
        self.key = self.generate_key(key_length)
        self.key = [84, 104, 97, 116, 115, 32, 109, 121, 32, 75, 117, 110, 103, 32, 70, 117]
        if debug:
            print("The original key! ", self.key)
        # Assuming the key_schedule method returns only the final_round_keys
        self.final_round_keys = self.key_schedule(self.key)
        if debug:
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

    def text_to_state_matrix(plaintext):
        state_matrix = []
        for col in range(4):
            column = []
            for row in range(4):
                if row * 4 + col < len(plaintext):
                    char = plaintext[row * 4 + col]
                    column.append(ord(char))  # Convert character to ASCII
                else:
                    column.append(0)  # If plaintext is shorter than 16 bytes, pad with 0
            state_matrix.append(column)
        return state_matrix

    def int_to_state_matrix(plaintext):
        state_matrix = []
        for col in range(4):
            column = []
            for row in range(4):
                if row * 4 + col < len(plaintext):
                    char = plaintext[row * 4 + col]
                    column.append(char)  # Convert character to ASCII
                else:
                    column.append(0)  # If plaintext is shorter than 16 bytes, pad with 0
            state_matrix.append(column)
        return state_matrix
    
    def encrypt(self, plaintext_bytes):
        ciphertext = bytearray()
        for i in range(0, len(plaintext_bytes), 16):
            block = plaintext_bytes[i:i+16]
            #print("Block to state matrix?", block)
            state_matrix = AES.text_to_state_matrix(block)

            #print("State matrix for plaintext block:", state_matrix)
            encrypted_block = self.cipher_block(state_matrix, mode=True)  # Assuming cipher_block accepts state matrix
            ciphertext.extend(encrypted_block.encode("utf-8"))
        return bytes(ciphertext)



    def decrypt(self, ciphertext_bytes):
        decipheredText = bytearray()
        for i in range(0, len(ciphertext_bytes), 16):
            block = ciphertext_bytes[i:i+16]
            state_matrix = AES.int_to_state_matrix(block)

            decrypted_block = self.cipher_block(state_matrix, mode=False)
            #print("Decrypted_block", decrypted_block)  # Add this line to print the decrypted block
            decipheredText.extend(decrypted_block.encode("utf-8"))

        #print("Deciphered Text before trying to remove padding", decipheredText)
        # Remove padding
        #deciphered_text = self.unpad_plaintext(decipheredText)

        #print("Unpadded text: ", deciphered_text)

        # Decode the plaintext
        try:
            plaintext_decoded = decipheredText.decode("utf-8")
            #print("Decoded text:", plaintext_decoded)
        except UnicodeDecodeError:
            #print("Unable to decode decrypted bytes as UTF-8. Trying to replace invalid sequences...")
            plaintext_decoded = decipheredText.decode("utf-8", errors="replace")
            #print("Decoded text (UTF-8, with invalid sequences replaced):", plaintext_decoded)

        return decipheredText

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
                #print("initial final round keys", final_round_keys)
            else:
                new_round_key = self.generate_round_key(final_round_keys[-1], i - 1) 
                final_round_keys.append(new_round_key)

        return final_round_keys


    def generate_round_key(self, key, round_num):
            #print("The round key number is:", round_num)
            prev_round_key = key.copy() 
            #print("The previous round key", prev_round_key)
            
            last_num = [word for word in prev_round_key[-1]]
            #print("The last word is ", last_num)
            new_key_word = self.generate_round_key_word(last_num, round_num)
            new_round_key = self.generate_new_round_keys(prev_round_key, new_key_word)
            return new_round_key
            
    def generate_round_key_word(self, last_num, round_num):
        # Rotate the numbers
        rotated_num = last_num[1:] + [last_num[0]]
        #print("The rotated num", rotated_num)

        transformed_bytes = []

        for byte in rotated_num:

            # Perform substitution using S-box
            substituted_byte = self.sub_bytes(byte, mode=True)
            
            transformed_bytes.append(substituted_byte)

        #print("The substituted result was", transformed_bytes)
        round_constants = self.get_round_constants(round_num)
        #print("The round constants are ", round_constants)
        xor_result = bytes([b1 ^ b2 for b1, b2 in zip(transformed_bytes, round_constants)])
        xor_list = [integer for integer in xor_result]
        #print("The XOR list", xor_list)
        return xor_list

    
    def generate_new_round_keys(self, prev_round_key, new_key_word):

        #print("The previous round key is: ", prev_round_key)
        new_round_keys = []

        #print("The_new_key word is ", new_key_word)

        for sub_key in prev_round_key:
                # XOR the new key word with each integer in the current list
                #print("What sub key im XORING ", sub_key)
                #print("What new key word Im xoring", new_key_word)
                xor_result = [b1 ^ b2 for b1, b2 in zip(sub_key, new_key_word)]
                #print("The result was:", xor_result)
                new_round_keys.append(xor_result)
                new_key_word = xor_result
        #print("The new round keys are: ", new_round_keys)

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
        if debug:
            print("Add Round Key")
            self.print_block_hex(block)
            print()

        for i in range(4):  # Iterate over columns
            for j in range(4):  # Iterate over rows
                #print("the block im trying to xor", block[j][i])
                #print("the round key im trying to xor", round_key[j][i])  # Use round_key directly
                block[j][i] ^= round_key[i][j]  # Perform XOR operation
                #print("The result is ", block[j][i])

        if debug:
            self.print_block_hex(block)
            print()

    def print_block_hex(self, block):
        for row in block:
            hex_row = " ".join(format(byte, '02X') for byte in row)
            print(hex_row)

    def cipher_block(self, block, mode):
        if mode:
            round_key = self.final_round_keys[0]
            self.add_round_key(block, round_key)

            num_rounds = 10 if len(self.key) == 16 else (12 if len(self.key) == 24 else 14)
            #print("Number of rounds", num_rounds)

            for round_num in range(1, num_rounds):
                # SubBytes
                self.sub_block(block, mode)

                # ShiftRows
                self.shift_rows(block, mode)

                # MixColumns (only for encryption mode)
                mixColumns.mix_columns(block)

                round_key = self.final_round_keys[round_num]
                self.add_round_key(block, round_key)

            self.sub_block(block, mode)
            self.shift_rows(block, mode)
            round_key = self.final_round_keys[num_rounds]
            self.add_round_key(block, round_key)
        else:
            num_rounds = 10 if len(self.key) == 16 else (12 if len(self.key) == 24 else 14)

            round_key = self.final_round_keys[num_rounds]
            self.add_round_key(block, round_key)
            self.shift_rows(block, mode)
            self.sub_block(block, mode)

            for round_num in range(num_rounds-1, 0, -1):
                round_key = self.final_round_keys[round_num]
                self.add_round_key(block, round_key)

                # MixColumns (only for encryption mode)
                mixColumns.inv_mix_columns(block)

                # ShiftRows
                self.shift_rows(block, mode)

                # SubBytes
                self.sub_block(block, mode)

            round_key = self.final_round_keys[0]
            self.add_round_key(block, round_key)

        cipher_block = ''
        for col in range(4):
            for row in range(4):
                cipher_block += str(block[row][col])

        return cipher_block

    def sub_block(self, block, mode):
        if debug:
            print("Sub Bytes")
            self.print_block_hex(block)
            print()

        for r in range(4):
            for c in range(4):
                if mode:
                    block[r][c] = SBox.encrypt(block[r][c])
                else:
                    block[r][c] = SBox.decrypt(block[r][c])

        if debug:
            self.print_block_hex(block)
            print()


    def sub_bytes(self, pByte, mode):
        result = None
        if mode:
            result = SBox.encrypt(pByte)
        else:
            result = SBox.decrypt(pByte)
        return result

    def shift_rows(self, block, mode):
        if debug:
            print("Shift Rows")
            self.print_block_hex(block)
            print()

        for r in range(1, 4):
            row = block[r]
            if mode:
                block[r] = row[r:] + row[:r]
            else:
                block[r] = row[:r] + row[r:]


        if debug:
            self.print_block_hex(block)
            print()

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
    plain_text = "the quick brown fox"
    print(f"Original Message: {plain_text}")

    rijndael = AES()
    cipher_text = rijndael.encrypt(plain_text)
    print(f"Encrypted Message: {cipher_text.decode("utf-8")}")

    decrypt_text = rijndael.decrypt(cipher_text)
    print(f"Decrypted Message: {decrypt_text}")
