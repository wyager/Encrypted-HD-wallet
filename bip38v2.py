# Will Yager's implementation of the in-development encrypted hierarchical deterministic wallet spec
# You may need to install slowaes and scrypt. All are available through `pip install [whatever]`
import aes 
import hashlib
import hmac
import scrypt
import os

# Encrypt with AES ECB. Key must be 32 bytes (256 bits). Data can be 16, 32, or 64 bytes.
def aes_encrypt(data, key):
    if len(data) != 16 and len(data) != 32 and len(data) != 64:
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

# Decrypt with AES ECB. Key must be 32 bytes (256 bits). Data can be 16, 32, or 64 bytes.
def aes_decrypt(data, key):
    if len(data) != 16 and len(data) != 32 and len(data) != 64:
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


# Hash with SHA 256
sha_hash = lambda data : hashlib.sha256(data).digest()

# Hash with RIPEMD-160
ripe_hash = lambda data : hashlib.new('ripemd160', data).digest()

# Hash with HMAC-SHA512
hmac_hash = lambda key, data : hmac.new(key, data, hashlib.sha512).digest()

# The various key derivation functions defined in the spec
kdf_functions = {
    0: lambda data, salt, output_len : scrypt.hash(data, salt, pow(2,14), 8, 8, output_len),
    1: lambda data, salt, output_len : scrypt.hash(data, salt, pow(2,16), 16, 16, output_len),
    2: lambda data, salt, output_len : scrypt.hash(data, salt, pow(2, 18), 16, 16, output_len),
}

# This checksum is used to verify that the user entered their password correctly
secret_checksum = lambda root_key : sha_hash(sha_hash(generate_master_secret(root_key)))[0:4]

def string_xor(a, b):
    result = ''
    for i in range(len(a)):
        result += chr(ord(a[i]) ^ ord(b[i]))
    return result

def generate_master_secret(root_key):
    """
    Compute generate_master_secret(root_key).
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


def encrypt_root_key(prefix, date, root_key, hash_function, passphrase):
    """
    Compute encrypt_root_key(prefix, date, root_key, hash_function, passphrase).
    root_key is a BIP 0032 root key. It should be a 16/32/64-byte string.
    date should be a 2-byte string (containing an unsigned integer)
    date can contain any date on or before the date this wallet was generated
    prefix should be a 3-byte string
    hash_function should be a function that takes a key, a salt, and a length L and outputs an L byte string.
    passphrase should be a string
    The returned value is the encrypted key as a string.
    This implementation differs a bit from the current draft spec. I'm using the hash of the
    private key instead of the hash of the master Bitcoin public address, in order to
    prevent someone from trivially determining the master Bitcoin public address, had it ever
    appeared in the blockchain.
    """
    if len(prefix) != 3: # prefix should be a raw 3 byte string
        raise Exception("Invalid prefix length: " + str(len(prefix)))
    if len(date) != 2: # Date should be a packed 2 byte integer
        raise Exception("Invalid date length: " + str(len(date)))
    if len(root_key) not in (16,32,64):
        raise Exception("root key needs to be 16/32/64 bytes, but is " + str(len(root_key)))
    if type(root_key) != type(""):
        raise Exception("root key needs to be a string")

    checksum = secret_checksum(root_key) # Used to verify that the user entered their password correctly upon decryption
    salt = prefix + date + checksum

    preH = hmac_hash(salt, passphrase)
    strongH = hash_function(preH, preH, 64)
    postH = hmac_hash(passphrase, salt)
    H = scrypt.hash(postH, strongH, pow(2,10), 1, 1, len(root_key) + 32)

    whitened_root_key = string_xor(root_key, H)

    encryption_key = H[-32:] # Use the last 32 bytes of H as a key
    encrypted_root_key = aes_encrypt(whitened_root_key, encryption_key)
    # Size:[3]      [2]    [4]        [16/32/64]
    return encrypted_root_key

def decrypt_root_key(encrypted_root_key, passphrase=None):
    """
    decrypt_root_key(encrypted_root_key, passphrase=None)
    Takes a byte string containing the encrypted root key and associated data (prefix, etc.)
    If the wallet is unencrypted, it is OK not to provide a passphrase
    and returns a tuple of (prefix, date, checksum, root key).
    """
    prefix = encrypted_root_key[0:3]
    date = encrypted_root_key[3:5]
    checksum = encrypted_root_key[5:9]
    salt = encrypted_root_key[0:9]
    encrypted_key = encrypted_root_key[9:]
    
    wallet_type = int(prefix[0:2].encode('hex'), 16)
    # This dictionary maps prefixes to (starting bottom byte values, key length, encrypted)
    # See the BIP spec for a better explanation. Look at the "prefixes" section.
    prefix_values = {0x0b2d: (0x7b, 16, False), 0x1482: (0x17, 32, False), 0x0130: (0xb7, 64, False), 0x14d6: (0x0d, 16, True), 0x263a: (0xa2, 32, True), 0x0238: (0x04, 32, True)}

    if wallet_type not in prefix_values:
        raise Exception("Unknown prefix")
    if prefix_values[wallet_type][2] == False: #Un-encrypted wallet
        return (prefix, date, checksum, encrypted_key)
    if len(encrypted_key) != prefix_values[wallet_type][1]:
        raise Exception("Length of key does not match length specified in prefix: " + len(encrypted_key))
    
    kdf_type = int(prefix[2].encode('hex'), 16) - prefix_values[wallet_type][0] # There are a number of KDF algorithms that might be in use
    
    hash_function = kdf_functions[kdf_type]

    preH = hmac_hash(salt, passphrase)
    strongH = hash_function(preH, preH, 64)
    postH = hmac_hash(passphrase, salt)
    H = scrypt.hash(postH, strongH, pow(2,10), 1, 1, len(encrypted_key) + 32)

    encryption_key = H[-32:] # Use the last 32 bytes of H as a key
    decrypted_key = aes_decrypt(encrypted_key, encryption_key) # The key, of length n, is still xored with the first n bits of H

    unwhitened_root_key = string_xor(decrypted_key, H)

    calculated_checksum = secret_checksum(unwhitened_root_key) # Used to verify that the user entered their password correctly upon decryption
    if checksum != calculated_checksum:
        raise Exception("Password incorrect. Checksum mismatch. Expected " + checksum.encode('hex') + " but calculated " + calculated_checksum.encode('hex'))
    return prefix, date, checksum, unwhitened_root_key



# Returns 16/32/64 bytes of random data that yields a valid private key when
# run through the BIP 0032 key -> secret algorithm.
def generate_root_key(length=32):
    """
    generate_root_key(length=32)
    generate a valid root key.
    len should be 16, 32, or 64.
    returns a string.
    """
    random_data = os.urandom(length)
    try:
        generate_master_secret(random_data) # Will throw an exception if this root key generates an invalid result. Happens very rarely, but can still happen.
    except Exception as e:
        return generate_root_key(length) # Try again.
    return random_data


def make_wallet(root_key, date, passphrase=None, kdf_type=0):
    """
    make_wallet(root_key, date, passphrase=None, kdf_type=0)
    root_key should be a 16, 32, or 64 byte string.
    Date should be an integer >= 0.
    passphrase (optional) should be a string. Providing a passphrase will enable encryption.
    kdf_type (optional) should be one of the values specified in the spec (0,1, or 2).
    0 is weakest, 2 is strongest. Anything stronger than 0 might not run on a mobile device.
    """
    if len(root_key) not in (16,32,64):
        raise Exception("root_key must be 16/32/64 bytes long.")
    generate_master_secret(root_key) # Will raise an exception if the root key is invalid
    if date < 0:
        raise Exception("Date must be positive integer")
    if kdf_type not in kdf_functions:
        raise Exception("Unknown KDF type")


    if passphrase is None: # Unencrypted wallet
        return make_unencrypted_wallet(root_key, date)
    else: # Encrypted wallet
        return make_encrypted_wallet(root_key, date, passphrase, kdf_type)

def make_unencrypted_wallet(root_key, date):
    prefix = {16: 0x0B2D7B, 32: 0x148217, 64: 0x0130B7}[len(root_key)]
    checksum = secret_checksum(root_key)

    byte_prefix = hex(prefix)[2:].decode('hex')
    byte_date = chr(date & 0xFF) + chr((date >> 8) & 0xFF)

    encrypted_key = root_key

    return byte_prefix+byte_date+checksum+encrypted_key


def make_encrypted_wallet(root_key, date, passphrase, kdf_type):
    prefix = {16: 0x14D60D, 32: 0x263AA2, 64: 0x023804}[len(root_key)] + kdf_type
    checksum = secret_checksum(root_key)

    byte_prefix = hex(prefix)[2:].decode('hex')
    byte_date = ("%04x" % date).decode('hex')

    hash_function = kdf_functions[kdf_type]

    encrypted_key = encrypt_root_key(byte_prefix, byte_date, root_key, hash_function, passphrase)

    return byte_prefix+byte_date+checksum+encrypted_key




