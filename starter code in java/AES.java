import java.util.Arrays;

public class AES {

    public final Integer[] keyLengths = {128, 192, 256};
    private int[] key;

    public AES()
    {
        int index = (int)(Math.random() * keyLengths.length);
        genKey(keyLengths[index]);
    }

    public AES(int keyLength)
    {
        genKey(keyLength);
    }

    public int getRandomLength()
    {
        int index = (int)(Math.random() * keyLengths.length);
        return keyLengths[index];
    }

    private void genKey(int keyLength)
    {
        key = new int[keyLength / 8];
        for (int i = 0; i < key.length; i++)
        {
            key[i] = randByte();
        }
    }

    private int randByte()
    {
        return (int)(Math.random() * 256);
    }

    public String encrypt(String plaintext)
    {
        return cipher(plaintext, true);
    }

    public String decrypt(String cipherText)
    {
        return cipher(cipherText, false);
    }

    private String cipher(String inText, boolean mode)
    {
        char[] charArray = inText.toCharArray();

        char[][] block = new char[4][4];
        StringBuilder outText = new StringBuilder();

        int index = 0;
        while(!getBlock(block, charArray, index))
        {
            outText.append(cipherBlock(block, mode));
            index += 16;
        }

        return outText.toString();
    }

    private boolean getBlock(char[][] block, char[] chars, int index)
    {
        boolean lastBlock = false;
        for (int col = 0; col < 4; col++)
        {
            for (int row = 0; row < 4; row++)
            {
                if (index >= chars.length)
                {
                    block[row][col] = (char)randByte();
                    lastBlock = true;
                } else {
                    block[row][col] = chars[index];
                    index++;
                }
            }
        }
        return lastBlock;
    }

    private String cipherBlock(char[][] block, boolean mode)
    {
        AddRoundKey(block);

        int numRounds = key.length / 4 + 5;

        for (int i = 0; i < numRounds; i++)
        {
            SubBytes(block, mode);
            ShiftRows(block);
            MixColumns(block);
            AddRoundKey(block);
        }

        SubBytes(block, mode);
        ShiftRows(block);
        AddRoundKey(block);

        String cipherBlock = "";
        for (int col = 0; col < 4; col++)
        {
            for (int row = 0; row < 4; row++)
            {
                cipherBlock += block[row][col];
            }
        }

        return cipherBlock;
    }

    private void AddRoundKey(char[][] block)
    {

    }

    private void SubBytes(char[][] block, boolean mode)
    {
        for (int r = 0; r < 4; r++)
        {
            for (int c = 0; c < 4; c++)
            {
                if (mode) {
                    block[r][c] = (char) SBox.encrypt(block[r][c]);
                } else {
                    block[r][c] = (char) SBox.decrypt(block[r][c]);
                }
            }
        }
    }

    private void ShiftRows(char[][] block)
    {
        for (int r = 1; r < 4; r++)
        {
            char[] temp = Arrays.copyOf(block[r], 4);
            for (int c = 0; c < 4; c++)
            {
                block[r][c] = temp[(c+r) % 4];
            }
        }
    }

    private void MixColumns(char[][] block)
    {

    }

    private void printBlock(char[][] block)
    {
        for(int r = 0; r < 4; r++)
        {
            for(int c = 0; c < 4; c++)
            {
                System.out.printf("%c ", (int)block[r][c]);
            }
            System.out.println();
        }
    }

    public static void main(String[] args)
    {
        String plainText = "The quick brown fox jumps over the lazy dog.  Lorem ipsum dolor sit amet.";

        AES rijndael = new AES();
        String cipherText = rijndael.encrypt(plainText);
        System.out.println(cipherText);

        String decryptText = rijndael.decrypt(cipherText);
        System.out.println(decryptText);
    }
}
