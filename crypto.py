# Will Yager's implementation of PBKDF2-HMAC-SHA512, as well as some important crypto utilities
# Note: This entire BIP can be implemented without scrypt, if you intend to put it on an embedded/mobile device

import aes 
import hashlib
import hmac
import scrypt

string_xor = lambda a,b : ''.join([chr(ord(x)^ord(y)) for (x,y) in zip(a,b)])


################ Simple Hashes ################

# Hash with SHA 256
sha_hash = lambda data : hashlib.sha256(data).digest()

# Hash with RIPEMD-160
ripe_hash = lambda data : hashlib.new('ripemd160', data).digest()

# Hash with HMAC-SHA512
hmac_hash = lambda key, data : hmac.new(key, data, hashlib.sha512).digest()


################ PBKDF2 ################

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


################ KDFs ################


def generate_master_secret(root_key):
    """
    generate_master_secret(root_key).
    root_key is a BIP 0032 root key. It should be a string.
    The returned value is a valid Bitcoin private key, in byte string format.
    """
    I = hmac_hash("Bitcoin seed", root_key) # See BIP 0032. This is used to generate the master secret and master chain.
    master_secret_string = I[0:32] # The value of the master secret, as a string
    master_secret = int(master_secret_string.encode('hex'), 16) # The integer value of the master secret
    curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if master_secret == 0 or master_secret >= curve_order:
        raise Exception("Specified root key generates invalid secret")
    return master_secret_string


# The various key derivation functions defined in the spec
kdf_functions = {
    0: lambda data, salt, output_len : scrypt.hash(data, salt, pow(2,14), 8, 8, output_len),
    1: lambda data, salt, output_len : scrypt.hash(data, salt, pow(2,16), 16, 16, output_len),
    2: lambda data, salt, output_len : scrypt.hash(data, salt, pow(2, 18), 16, 16, output_len),
    8: lambda data, salt, output_len : pbkdf2(data, salt, pow(2,16), output_len),
    9: lambda data, salt, output_len : pbkdf2(data, salt, pow(2,21), output_len)
}


################ Verification ################

# This checksum is used to verify that the user entered their unencrypted waller correctly
secret_checksum = lambda root_key : sha_hash(sha_hash(generate_master_secret(root_key)))


# Used to verify the user entered their password correctly for an encrypted wallet
def bloom_filter(items):
    """
    bloom_filter(items)
    Constructs a 32-bit bloom filter
    inserts all elements of items
    returns the 32-bit filter as a 4-byte string.
    """
    result = 0
    for item in items:
        for value in secret_checksum(item)[0:11]:
            element = ord(value) & 0x1F
            result |= 1 << element
    return chr(result & 0xFF) + chr((result >> 8) & 0xFF) + chr((result >> 16) & 0xFF) + chr((result >> 24) & 0xFF)

def bloom_filter_contains(other_filter, item):
    """
    bloom_filter_contains(other_filter, item)
    other_filter is a 4-byte string
    returns if item might be an element of other_filter
    """
    item_only_filter = bloom_filter([item])
    for i in range(4):
        if (ord(other_filter[i]) & ord(item_only_filter[i])) != ord(item_only_filter[i]): #Make sure that all the proper bits are set in the filter
            return False
    return True




