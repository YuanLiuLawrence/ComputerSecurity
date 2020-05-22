import hashlib


if __name__ == '__main__':
    hasher = hashlib.sha512()
    hasher.update(b'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')
    # hasher.update(message)
    with open('output2.txt','w') as fp:
        fp.write(hasher.hexdigest())
    print(hasher.hexdigest())
