#!/usr/bin/env python3.6

# Homework Number: 04
# Name: Yuan Liu
# ECN login: liu1827
# Due Date: 03/03/2020

from BitVector import *
from PrimeGenerator import *
from solve_pRoot import *
import sys


e = 3
BLOCKSIZE = 256

# Calculate GCD of a and b to check co-primality
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# Generate the p and q as requested
def generation():
    generator = PrimeGenerator(bits=128)
    while True:
        # Generate p and q using Provided Prime Generator and change to bitvector to test the first two bits
        p = BitVector(intVal=generator.findPrime(), size=128)
        q = BitVector(intVal=generator.findPrime(), size=128)
        # p and q can not be equal
        if p != q:
            # First two bits of p and q have to be set
            if q[0] and q[1] and p[1] and p[0]:
                # p-1 and q-1 have be co-prime to e
                if gcd((p.int_val()-1), e) and gcd(q.int_val()-1, e):
                    # All the constraints satisfied, return the values of p and q
                    # with open(p_file, "w") as fp:
                    #    fp.write(str(p.int_val()))
                    # with open(q_file, "w") as fp:
                    #    fp.write(str(q.int_val()))
                    return p.int_val(), q.int_val()


# argv[0]: message.txt
# argv[1]: enc1.txt
# argv[2]: enc2.txt
# argv[3]: enc3.txt
# argv[4]: n_1_2_3.txt
# Encryption for RSA
def encryption(argv):
    public = []
    # print(argv)
    for i in range(1, 4):
        # Generate p and q for public key
        p, q = generation()

        # Check the difference of every n
        while (p * q) in public:
            p, q = generation()
        # Store the public key n to the list
        public.append(p * q)

        # Debug use
        # n = BitVector(intVal=p*q)
        # print(public, len(n))

        # Write to the corresponding file
        encryption_one_time(argv[0], p * q, argv[i])

    # Write to "n_1_2_3.txt"
    with open(argv[-1], "w") as fp:
        for i in range(3):
            fp.write(str(public[i]) + '\n')
    return


# Encryption for RSA for one public key
def encryption_one_time(in_file, n, out_file):
    # Reading from the input file
    bv = BitVector(filename=in_file)
    with open(out_file, 'w') as fp:
        while bv.more_to_read:
            bitvec = bv.read_bits_from_file(128)
            if bitvec.length() > 0:
                # Padding zeros to insufficient block
                if bitvec.length() < 128:
                    bitvec.pad_from_right(128 - bitvec.length())
                # Padding zeros to left to form a 256 size block
                bitvec.pad_from_left(128)
                # Encrypt the plaintext after raise to the power of e and modules n
                final_bitvec = BitVector(intVal=pow(bitvec.int_val(), e, n), size=256)
                fp.write(final_bitvec.get_bitvector_in_hex())
    return


# argv[0]: enc1.txt
# argv[1]: enc2.txt
# argv[2]: enc3.txt
# argv[3]: n_1_2_3.txt
# argv[4]: cracked.txt
# Crack for RSA
def crack(argv):
    # Store all the keys in "n_1_2_3.txt"
    keys = []
    # Store the values for Ni and Ni_MI
    N_i_result = []
    # Store the multiple result of n(s)
    N = 1
    # Store the bitvec in enc[x].txt
    bv = []

    # Read the public keys from "n_1_2_3.txt"
    with open(argv[3], "r") as fp:
        for i in range(3):
            # print(int(fp.readline().strip()))
            # print(fp.read().strip("\n"))
            key = int(fp.readline().strip("\n"))
            # Calculate the value of N
            N *= key
            keys.append(key)

    # print(N)
    # print(keys)
    with open(argv[-1], "wb") as fp:

        # Calculate the length of file
        # Three encrypted file should have the same length
        File_in = open(argv[0])
        # print(len(File_in.read()))
        bv_calc = BitVector(hexstring=File_in.read())
        File_in.close()
        LOF = bv_calc.length()
        # print(LOF // BLOCKSIZE) # debug helper

        # Attack the cipher text by blocks
        for rd in range(0, LOF // BLOCKSIZE):
            Cube = 0
            for i in range(3):
                # According to the lecture 12 p.98
                # Calculate the MI for each N_i and the result for Ni * Ni_MI
                N_i = N // keys[i]
                N_i_bv = BitVector(intVal=N_i)
                N_i_MI = N_i_bv.multiplicative_inverse(BitVector(intVal=keys[i])).int_val()
                N_i_result.append(N_i * N_i_MI)

                # Read the hexstring from the encrypted file
                File_in = open(argv[i])
                bv.append(BitVector(hexstring=File_in.read()))
                File_in.close()

                # Padding zeros to the end of the file if the length of the file can not
                # be divided by 256
                if len(bv[i]) % BLOCKSIZE:
                    bv[i].pad_from_right(BLOCKSIZE - len(bv[i]) % BLOCKSIZE)

                # Adding block in three encrypted files together
                Cube += bv[i][rd * BLOCKSIZE:(rd + 1) * BLOCKSIZE].int_val() * N_i_result[i]

            # Calculate the M^3
            Cube %= N

            # Calculate the M (Decrypt the M)
            M = solve_pRoot(3, Cube)

            M_bv = BitVector(intVal=M, size=256)[128:]
            # print(rd, M_bv) # debug helper
            if rd != (LOF // BLOCKSIZE - 1):
                M_bv.write_to_file(fp)
            else:
                # Exclude the zeros padded when read the file
                for bit in range(0, len(M_bv) // 8):
                    block = M_bv[bit * 8: (bit + 1) * 8]
                    if block.int_val() != 0:
                        block.write_to_file(fp)
    return


if __name__ == '__main__':
    # print(sys.argv)
    if sys.argv[1] == '-e':
        encryption(sys.argv[2:])
        print("Successfully Encrypted")
    elif sys.argv[1] == '-c':
        crack(sys.argv[2:])
        print("Successfully Cracked")
