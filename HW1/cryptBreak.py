# Homework Number: 01
# Name:  Yuan Liu
# ECN Login: liu1827
# Due Date:  1/23/2020

# Arguments:
# ciphertextFile: String containing file name of the ciphertext (e.g. encrypted.txt )
# key_bv: 16-bit BitVector of the key used to try to decrypt the ciphertext.

# Function Description:
# Attempts to decrypt ciphertext contained in ciphertextFile using key_bv and returns
# the original plaintext as a string

from BitVector import *


def cryptBreak(ciphertextFile, key_bv):
    BLOCKSIZE = 16

    # Create a null bitvector:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)

    # Create a bitvector from the ciphertext hex string:
    FILEIN = open(ciphertextFile)
    encrypted_bv = BitVector(hexstring=FILEIN.read())

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector(size=0)

    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i * BLOCKSIZE:(i + 1) * BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^= previous_decrypted_block
        previous_decrypted_block = temp
        bv ^= key_bv
        msg_decrypted_bv += bv

    # Extract plaintext from the decrypted bitvector:
    outputtext = msg_decrypted_bv.get_text_from_bitvector()

    return outputtext


if __name__ == '__main__':
    for key in range(0, 2 ** 16):
        someRandomInteger = key  # Arbitrary integer for creating a BitVector
        key_bv = BitVector(intVal=someRandomInteger, size=16)
        decryptedMessage = cryptBreak('encrypted.txt', key_bv)
        if 'Mark Twain' in decryptedMessage:
            print('Encryption Broken!')
            print('The message is: ', decryptedMessage)
            print('The key is: ', key)
            break

