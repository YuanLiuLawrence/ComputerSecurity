#!/usr/bin/env python3.6

# Homework Number: 04
# Name: Yuan Liu
# ECN login: liu1827
# Due Date: 2/18/2020

import sys
from BitVector import *
AES_modulus = BitVector(bitstring='100011011')
subBytesTable = []  # for encryption
invSubBytesTable = []  # for decryption
BLOCKSIZE = 128
mix_column = {i: None for i in range(4)}
mix_column[0] = [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")]
mix_column[1] = [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")]
mix_column[2] = [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")]
mix_column[3] = [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
inv_mix_column = {i: None for i in range(4)}
inv_mix_column[0] = [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")]
inv_mix_column[1] = [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")]
inv_mix_column[2] = [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")]
inv_mix_column[3] = [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]


# goal here is to construct two 256-element arrays for byte substitution, one for
# the SubBytes step and the other for the InvSubBytes step
def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal=i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable, invSubBytesTable


# g() function used in lecture slides to generate the keywords
def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant


# generate the keywords used in each round of AES
def gen_key_schedule_256(key_bv):
    byte_sub_table, _ = genTables()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal=0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32:i*32+32]
    for i in range(8, 60):
        if i % 8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size=0)
            for j in range(4):
                key_words[i] += BitVector(intVal=byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size=8)
            key_words[i] ^= key_words[i-8]
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words


# Generate round keys used in AES
def gen_round_keys(key_words, key_schedule, num_rounds):
    for word_index, word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i * 8:i * 8 + 8].intValue())
        key_schedule.append(keyword_in_ints)
    round_keys = [None for i in range(num_rounds + 1)]
    for i in range(num_rounds + 1):
        round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] +
                         key_words[i * 4 + 3])
    return round_keys


# Function for mixing column
def Mix_Column(state_array):
    result_state_array = [[0 for x in range(4)] for x in range(4)]
    for l in range(4):
        for r in range(4):
            new_bytes = BitVector(size=8)
            for c in range(4):
                new_bytes ^= state_array[c][l].gf_multiply_modular(mix_column[r][c], AES_modulus, 8)
            result_state_array[r][l] = new_bytes
    return result_state_array


# Function for inverse mixing column
def Inv_Mix_Column(state_array):
    result_state_array = [[0 for x in range(4)] for x in range(4)]
    for l in range(4):
        for r in range(4):
            new_bytes = BitVector(size=8)
            for c in range(4):
                new_bytes ^= state_array[c][l].gf_multiply_modular(inv_mix_column[r][c], AES_modulus, 8)
            result_state_array[r][l] = new_bytes
    return result_state_array


# Function for encryption
# (a) Single-byte based substitution
# (b) Row-wise permutation
# (c) Column-wise mixing
# (d) Addition of the round key
def encrypt(inFile, outFile):
    num_rounds = 14

    # Read the key and generate key schedule
    with open('key.txt', 'r') as fp:
        key = fp.read()
    key = key.strip()
    key_bv = BitVector(textstring=key)
    key_words = gen_key_schedule_256(key_bv)
    key_schedule = []

    # Get round keys calculated by gen_round_keys
    round_keys = gen_round_keys(key_words, key_schedule, num_rounds)

    # Initialize a new state array with all zero (get from lecture notes)
    state_array = [[0 for x in range(4)] for x in range(4)]

    # Reading from the input file
    bv = BitVector(filename=inFile)
    with open(outFile, 'w') as fp:
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(128)
            if bitvec.length() > 0:
                # Padding zeros to insufficient block
                if bitvec.length() < 128:
                    bitvec.pad_from_right(128 - bitvec.length())

            # Add round key by XORing with content
            bitvec = bitvec ^ round_keys[0]

            # Fill in the state array by bytes in bitvec (get from the lecture notes)
            # for i in range(4):
            #    for j in range(4):
            #        state_array[j][i] = bitvec[32 * i + 8 * j:32 * i + 8 * (j + 1)]
            # Start the round of the AES (14 rounds for 256 key size)
            for i in range(1, 15):
                # Fill in the state array by bytes in bitvec (get from the lecture notes) and updated it every time
                for r in range(4):
                    for c in range(4):
                        state_array[c][r] = bitvec[32 * r + 8 * c:32 * r + 8 * (c + 1)]

                # SubBytes
                for r in range(4):
                    for c in range(4):
                        state_array[r][c] = BitVector(intVal=subBytesTable[int(state_array[r][c])], size=8)
                # Debug helper
                # if i == 1:
                #    bitvec = BitVector(size=0)
                #    for r in range(4):
                #        for c in range(4):
                #            bitvec += state_array[c][r]
                #     print("after sub:", bitvec.get_bitvector_in_hex())

                # ShiftRows
                for r in range(1, 4):
                    state_array[r] = state_array[r][r:] + state_array[r][:r]
                # Debug helper
                # if i == 1:
                #    bitvec = BitVector(size=0)
                #    for r in range(4):
                #        for c in range(4):
                #            bitvec += state_array[c][r]
                #     print("after shift:", bitvec.get_bitvector_in_hex())

                # Mixcolumns
                if i != 14:
                    state_array = Mix_Column(state_array)
                # Debug helper
                # if i == 1:
                #    bitvec = BitVector(size=0)
                #    for r in range(4):
                #        for c in range(4):
                #            bitvec += state_array[c][r]
                #    print("after mix:", bitvec.get_bitvector_in_hex())

                # Transform the state array to bit vector
                bitvec = BitVector(size=0)
                for r in range(4):
                    for c in range(4):
                        bitvec += state_array[c][r]

                # Add round key
                bitvec ^= round_keys[i]
                # Debug helper
                # if i == 1:
                #    print("after add:", bitvec.get_bitvector_in_hex())

                # Write to the file
            fp.write(bitvec.get_bitvector_in_hex())
    return


# Function for decryption
# (a) Inv Row-wise permutation
# (b) Inv Single-byte based substitution
# (c) Addition of the round key
# (d) Inv Column-wise mixing
def decrypt(inFile, outFile):
    num_rounds = 14

    # Read the key and generate key schedule
    with open('key.txt', 'r') as fp:
        key = fp.read()
    key = key.strip()
    key_bv = BitVector(textstring=key)
    key_words = gen_key_schedule_256(key_bv)
    key_schedule = []

    # Get round keys calculated by gen_round_keys
    round_keys = gen_round_keys(key_words, key_schedule, num_rounds)
    # Initialize a new state array with all zero (get from lecture notes)
    state_array = [[0 for x in range(4)] for x in range(4)]

    # Read the hexstring from the encrypted file
    File_in = open(inFile)
    bv = BitVector(hexstring=File_in.read())
    File_in.close()

    # Padding zeros to the end of the file if the length of the file can not
    # be divided by 128
    if len(bv) % BLOCKSIZE:
        bv.pad_from_right(BLOCKSIZE - len(bv) % BLOCKSIZE)
    with open(outFile, "wb") as fp:
        for rd in range(0, len(bv) // BLOCKSIZE):
            bitvec = bv[rd * BLOCKSIZE:(rd + 1) * BLOCKSIZE]
            if len(bitvec) > 0:
                bitvec ^= round_keys[-1]

                # Fill in the state array by bytes in bitvec (get from the lecture notes)
                # for i in range(4):
                #    for j in range(4):
                #        state_array[j][i] = bitvec[32 * i + 8 * j:32 * i + 8 * (j + 1)]

                for i in range(13, -1, -1):
                    # Fill in the state array by bytes in bitvec (get from the lecture notes) and updated it every time
                    for r in range(4):
                        for c in range(4):
                            state_array[c][r] = bitvec[32 * r + 8 * c:32 * r + 8 * (c + 1)]

                    # Inv shift rows
                    for r in range(1, 4):
                        state_array[r] = state_array[r][4-r:] + state_array[r][:4-r]

                    # Inv subBytes
                    for r in range(4):
                        for c in range(4):
                            state_array[r][c] = BitVector(intVal=invSubBytesTable[int(state_array[r][c])], size=8)

                    # Transform the state array to bit vector
                    bitvec = BitVector(size=0)
                    for r in range(4):
                        for c in range(4):
                            bitvec += state_array[c][r]

                    # Add round key
                    bitvec ^= round_keys[i]
                    #print(bitvec)
                    # Transform the bit vector to state array
                    for r in range(4):
                        for c in range(4):
                            state_array[c][r] = bitvec[32 * r + 8 * c:32 * r + 8 * (c + 1)]

                    # Inv column
                    if i != 0:
                        state_array = Inv_Mix_Column(state_array)
                    #print(state_array)
                    # Transform the state array to bit vector
                    bitvec = BitVector(size=0)
                    for r in range(4):
                        for c in range(4):
                            bitvec += state_array[c][r]
                    #print(bitvec)
            # Write to the output file
            bitvec.write_to_file(fp)
    return


if __name__ == '__main__':
    if sys.argv[1] == '-e':
        encrypt(sys.argv[2], sys.argv[-1])
    elif sys.argv[1] == '-d':
        decrypt(sys.argv[2], sys.argv[-1])