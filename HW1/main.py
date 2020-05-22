import cryptBreak
from BitVector import *
for key in range(0, 2**16):
    someRandomInteger = key  # Arbitrary integer for creating a BitVector
    key_bv = BitVector(intVal=someRandomInteger, size=16)
    decryptedMessage = cryptBreak.cryptBreak('encrypted.txt', key_bv)
    if 'Mark Twain' in decryptedMessage:
        print('Encryption Broken!')
        print(key)
        break
    else:
        print('Not decrypted yet')
        print(key)
