#!/usr/bin/env python3

# Homework Number: 06
# Name: Yuan Liu
# ECN login: liu1827
# Due Date: 03/03/2020

from BitVector import *
from PrimeGenerator import *
import sys

e = 65537
BLOCKSIZE = 256


# Calculate GCD of a and b to check co-primality
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


# Generate the p and q as requested
def generation(p_file, q_file):
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
                    # All the constraints satisfied, write to the corresponding file
                    with open(p_file, "w") as fp:
                        fp.write(str(p.int_val()))
                    with open(q_file, "w") as fp:
                        fp.write(str(q.int_val()))
                    return


# Encryption for RSA
def encryption(in_file, p_file, q_file, out_file):
    # Calculate n by reading p and q from the files
    p = int(open(p_file, "r").readline())
    q = int(open(q_file, "r").readline())
    n = p * q

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


# Decryption for RSA
def decryption(in_file, p_file, q_file, out_file):
    # Calculate n by reading p and q from the files
    p = int(open(p_file, "r").readline())
    q = int(open(q_file, "r").readline())
    n = p * q
    # Calculate the totient of n
    tn_n = (p - 1) * (q - 1)
    tn_n_bv = BitVector(intVal=tn_n)

    # Calculate the value of d , which is the MI of e mod tn_n by using built in function
    # (Followed from Lecture notes)
    # print(BitVector(intVal=e).multiplicative_inverse(tn_n_bv))
    d_bv = BitVector(intVal=e).multiplicative_inverse(tn_n_bv)

    # Read the hexstring from the encrypted file
    File_in = open(in_file)
    bv = BitVector(hexstring=File_in.read())
    File_in.close()

    # Padding zeros to the end of the file if the length of the file can not
    # be divided by 256
    if len(bv) % BLOCKSIZE:
        bv.pad_from_right(BLOCKSIZE - len(bv) % BLOCKSIZE)
    with open(out_file, "wb") as fp:
        for rd in range(0, len(bv) // BLOCKSIZE):
            bitvec = bv[rd * BLOCKSIZE:(rd + 1) * BLOCKSIZE]
            # print(bitvec)
            # Following the CRT methods illustrated in the lecture notes
            p_bv = BitVector(intVal=p)
            q_bv = BitVector(intVal=q)
            V_p = pow(bitvec.int_val(), d_bv.int_val(), p)
            V_q = pow(bitvec.int_val(), d_bv.int_val(), q)
            X_p = q * q_bv.multiplicative_inverse(p_bv).int_val()
            X_q = p * p_bv.multiplicative_inverse(q_bv).int_val()
            plain_bv = BitVector(intVal=((V_p * X_p + V_q * X_q) % n), size=256)[128:]
            # print(plain_bv)
            # print(rd, plain_bv) # debug helper
            if rd != ((len(bv) // BLOCKSIZE) - 1):
                plain_bv.write_to_file(fp)
            else:
                # Exclude the zeros padded when read the file
                for bit in range(0, len(plain_bv) // 8):
                    block = plain_bv[bit * 8: (bit + 1) * 8]
                    if block.int_val() != 0:
                        block.write_to_file(fp)
    return


if __name__ == '__main__':
    if sys.argv[1] == '-g':
        generation(sys.argv[-2], sys.argv[-1])
        print("Successfully Generated")
    elif sys.argv[1] == '-e':
        encryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        print("Successfully Encrypted")
    elif sys.argv[1] == '-d':
        decryption(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
        print("Successfully Decrypted")
    else:
        sys.exit("Wrong Argument")