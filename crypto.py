# Will Yager's implementation of PBKDF2-HMAC-SHA512, as well as some important crypto utilities
# https://github.com/wyager/Encrypted-HD-wallet

import aes 
from hashlib import sha512
import hmac
import scrypt
import os

def string_xor(a,b): 
    if len(a) != len(b):
        raise Exception("xor string length mismatch")
    return ''.join([chr(ord(x)^ord(y)) for (x,y) in zip(a,b)])


# Hash with HMAC-SHA512
hmac_hash = lambda key, data : hmac.new(key, data, sha512).digest()


################ PBKDF2 ################

# Note: This is a fully fleshed out implementation to 
# minimize the number of external dependencies and to give
# a clear example of how PBKDF2 is implemented. However,
# there are faster solutions for production code. With 
# the PyCrypto libraries installed, using this code:
#   from Crypto.Protocol.KDF import PBKDF2
#   from Crypto.Hash import SHA512
#   from Crypto.Hash import HMAC
#   hmac_hash = lambda key, msg : HMAC.new(key, msg, SHA512).digest()
#   pbkdf2 = lambda password, salt, len, count : PBKDF2(password, salt, len, count, hmac_hash)
# is about twice as fast.

pbkdf2_U = hmac_hash

def pbkdf2_F(password, salt, iterations, i):
    result = '\0'*64
    U = salt + chr((i>>24) & 0xFF) + chr((i>>16) & 0xFF) + chr((i>>8) & 0xFF) + chr((i>>0) & 0xFF)
    for i in xrange(iterations):
        U = pbkdf2_U(password, U)
        result = string_xor(result, U)
    return result

def pbkdf2(password, salt, iterations, output_len):
    """
    pbkdf2(password, salt, iterations, output_len)
    Computes PBKDF2-HMAC-SHA512 with the given arguments
    """
    output_blocks = output_len // 64
    if (output_len % 64) != 0:
        output_blocks += 1
    result = ''
    for i in range(1,output_blocks+1):
        result += pbkdf2_F(password, salt, iterations, i)
    return result[0:output_len]


################ AES ################

def aes_encrypt(data, key):
    """
    aes_encrypt(data, key)
    Encrypt with AES ECB.
    data can be 16/32/64 bytes.
    key must be 32 bytes (256 bits).
    """
    if len(data) not in (16, 32, 64):
        raise Exception("Data is incorrect length: " + str(len(data)))
    if len(key) != 32:
        raise Exception("Key is incorrect length: " + str(len(key)))
    key = map(ord, key) # Convert key and data to a list of ints
    data = map(ord, data)
    e = aes.AES()
    result = ''
    for i in range(len(data)/16):
        block = e.encrypt(data[16*i : 16*i + 16], key, 32)
        result = result + ''.join(map(chr, block))
    return result

def aes_decrypt(data, key):
    """
    aes_decrypt(data, key)
    Decrypt with AES ECB.
    data can be 16/32/64 bytes.
    key must be 32 bytes (256 bits).
    """
    if len(data) not in (16, 32, 64):
        raise Exception("Data is incorrect length: " + str(len(data)))
    if len(key) != 32:
        raise Exception("Key is incorrect length: " + str(len(key)))
    key = map(ord, key) # Convert key and data to a list of ints
    data = map(ord, data)
    e = aes.AES()
    result = ''
    for i in range(len(data)/16):
        block = e.decrypt(data[16*i : 16*i + 16], key, 32)
        result = result + ''.join(map(chr, block))
    return result


def encrypt_key(key, salt, passphrase, kdf):
    assert(len(key) == 32)

    H = stretch(passphrase, salt, kdf)

    whitened_key = string_xor(key, H[0:32])
    encryption_key = H[32:64]

    encrypted_root_key = aes_encrypt(whitened_key, encryption_key)
    return encrypted_root_key

def decrypt_key(encrypted_key, salt, passphrase, kdf):
    assert(len(encrypted_key) == 32)

    H = stretch(passphrase, salt, kdf) 

    encryption_key = H[32:64]
    whitened_key = aes_decrypt(encrypted_key, encryption_key)

    key = string_xor(whitened_key, H[0:32])
    return key


################ KDFs ################

# The various key derivation functions defined in the spec
kdfs = {
    0: lambda data, salt, output_len : scrypt.hash(data, salt, pow(2,14), 8, 8, output_len),
    1: lambda data, salt, output_len : scrypt.hash(data, salt, pow(2,16), 16, 16, output_len),
    2: lambda data, salt, output_len : scrypt.hash(data, salt, pow(2, 18), 16, 16, output_len),
    8: lambda data, salt, output_len : pbkdf2(data, salt, pow(2,16), output_len),
    9: lambda data, salt, output_len : pbkdf2(data, salt, pow(2,21), output_len)
}

def stretch(passphrase, salt, kdf):
    preH = pbkdf2(salt, passphrase, 10000, 64)
    strongH = kdf(preH[0:32], preH[0:32], 64)
    # We want 32 bytes for whitening, 32 for AES key
    return pbkdf2(preH, strongH, 1, 32+32) 

################ Verification ################

# Make a checksum of both keys,
# and then return them in ascending order (big endian)
def make_key_checksum(key1, key2):
    hash1 = sha512(key1).digest()[0:2]
    hash2 = sha512(key2).digest()[0:2]
    big_endian = lambda x : ord(x[1]) + ord(x[0]) << 8
    if big_endian(hash1) < big_endian(hash2):
        return hash1 + hash2
    else:
        return hash2 + hash1

# Check if the given key matches either part of the checksum
def check_key_checksum(key, checksum):
    key_hash = sha512(key).digest()[0:2]
    if key_hash == checksum[0:2] or key_hash == checksum[2:4]:
        return True
    else:
        return False


