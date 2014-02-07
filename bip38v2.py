# Will Yager's implementation of the in-development encrypted hierarchical deterministic wallet spec
# You may need to install slowaes and scrypt. All are available through `pip install [whatever]`
import os
import crypto

def encrypt_root_key(root_key, salt, passphrase, hash_function):
    """
    encrypt_root_key(root_key, salt, passphrase, hash_function).
    root_key is a BIP 0032 root key. It should be a 16/32/64-byte string.
    salt is prefix+date+entropy
    passphrase should be a byte string (utf-8)
    hash_function should be a function that takes a key, a salt, and a length L and outputs an L byte string.
    The returned value is the encrypted key as a string.
    """

    if len(root_key) not in (16,32,64):
        raise Exception("root key needs to be 16/32/64 bytes, but is " + str(len(root_key)))
    if type(root_key) != type(""):
        raise Exception("root key needs to be a string")

    preH = crypto.hmac_hash(salt, passphrase)
    strongH = hash_function(preH, preH, 64)
    postH = crypto.hmac_hash(passphrase, salt)
    H = crypto.pbkdf2(postH, strongH, pow(2,10), len(root_key) + 32)

    whitened_root_key = crypto.string_xor(root_key, H[0:-32])

    encryption_key = H[-32:] # Use the last 32 bytes of H as a key
    encrypted_root_key = crypto.aes_encrypt(whitened_root_key, encryption_key)

    return encrypted_root_key


def decrypt_root_key(encrypted_key, salt, passphrase, hash_function):
    """
    decrypt_root_key(encrypted_key, salt, passphrase, hash_function).
    encrypted_key is a 16/32/64 byte string
    salt is prefix+date+entropy
    passphrase should be a byte string (utf-8)
    hash_function should be a function that takes a key, a salt, and a length L and outputs an L byte string.
    The returned value is the unencrypted key as a string.
    """
    preH = crypto.hmac_hash(salt, passphrase)
    strongH = hash_function(preH, preH, 64)
    postH = crypto.hmac_hash(passphrase, salt)
    H = crypto.pbkdf2(postH, strongH, pow(2,10), len(encrypted_key) + 32)

    encryption_key = H[-32:] # Use the last 32 bytes of H as a key
    decrypted_key = crypto.aes_decrypt(encrypted_key, encryption_key) # The key, of length n, is still xored with the first n bits of H

    unwhitened_root_key = crypto.string_xor(decrypted_key, H[0:-32])

    return unwhitened_root_key


def decrypt_wallet(encrypted_wallet, passphrase=None):
    """
    decrypt_root_key(encrypted_wallet, passphrase=None)
    Takes a byte string (not encoded - raw bytes) containing the encrypted root key and associated data (prefix, etc.)
    If the wallet is unencrypted, it is OK not to provide a passphrase
    Passphrase must be a byte string (ascii or utf-8 characters only)
    and returns a tuple of (prefix, date, checksum/bloom filter, root key).
    """
    prefix = encrypted_wallet[0:2]
    
    wallet_type = int(prefix[0:2].encode('hex'), 16)
    # This dictionary maps prefixes to (wallet length, entropy length, is encrypted)
    # See the BIP spec for a better explanation. Look at the "prefixes" section.
    prefix_values = {0x28C1: (24, 0, False), 0x4AC5: (40, 0, False), 0xFBB3: (72, 0, False), 0xF83F: (26, 2, True), 0x6731: (43, 3, True), 0x4EB4: (76, 4, True)}

    if wallet_type not in prefix_values:
        raise Exception("Unknown wallet type: " + hex(wallet_type))

    wallet_len, entropy_len, is_encrypted = prefix_values[wallet_type]

    if len(encrypted_wallet) != wallet_len:
        raise Exception("Length of encrypted wallet does not match length specified in prefix: " + str(len(encrypted_wallet)))

    if not is_encrypted:
        # [2 byte prefix][2 byte date][4 byte checksum][16/32/64 byte key, per prefix]
        date = encrypted_wallet[2:4]
        checksum = encrypted_wallet[4:8]
        root_key = encrypted_wallet[8:]
        if checksum != crypto.secret_checksum(root_key)[0:4]:
            raise Exception("Checksum mismatch. Ensure the wallet was entered correctly")
        return (prefix, date, checksum, root_key)

    elif is_encrypted:
        # [2 byte prefix][2 byte date][2/3/4 byte entropy+kdf, per prefix][4 byte bloom filter][16/32/64 byte key, per prefix]
        date = encrypted_wallet[2:4]
        entropy = encrypted_wallet[4:4+entropy_len]
        bloom_filter = encrypted_wallet[4+entropy_len:8+entropy_len]
        encrypted_key = encrypted_wallet[8+entropy_len:]
        salt = prefix+date+entropy
        
        kdf_type = ord(entropy[0])>>3 # The chosen KDF number goes in the top 5 bits of entropy
        hash_function = crypto.kdf_functions[kdf_type]

        decrypted_root_key = decrypt_root_key(encrypted_key, salt, passphrase, hash_function)
        if not crypto.bloom_filter_contains(bloom_filter, decrypted_root_key):
            raise Exception("Password incorrect.")

        return (prefix, date, bloom_filter, decrypted_root_key)



# Returns 16/32/64 bytes of random data that yields a valid private key when
# run through the BIP 0032 key -> secret algorithm.
def generate_root_key(length=32):
    """
    generate_root_key(length=32)
    generate a valid root key.
    length should be 16, 32, or 64.
    returns a string.
    """
    random_data = os.urandom(length)
    try:
        crypto.generate_master_secret(random_data) # Will throw an exception if this root key generates an invalid result. Happens very rarely, but can still happen.
    except Exception as e:
        return generate_root_key(length) # Try again.
    return random_data


def make_wallet(root_key, date, passphrase=None, fake_passphrase = None, kdf_type=0):
    """
    make_wallet(root_key, date, passphrase=None, kdf_type=0)
    root_key should be a 16, 32, or 64 byte string.
    Date should be an integer >= 0.
    passphrase (optional) should be a string. Providing a passphrase will enable encryption.
    kdf_type (optional) should be one of the values specified in the spec (0,1,2, 8, or 9).
    0,1,2 are scrypt, with 0 weakest and 2 strongest. 8,9 are PBKDF2-HMAC-SHA512, with 9 strongest.
    """
    if len(root_key) not in (16,32,64):
        raise Exception("root_key must be 16/32/64 bytes long.")
    crypto.generate_master_secret(root_key) # Will raise an exception if the root key is invalid
    if date < 0:
        raise Exception("Date must be positive integer")
    if kdf_type not in crypto.kdf_functions:
        raise Exception("Unknown KDF type")


    if passphrase is None: # Unencrypted wallet
        return make_unencrypted_wallet(root_key, date)
    else: # Encrypted wallet
        return make_encrypted_wallet(root_key, date, kdf_type, passphrase, fake_passphrase = fake_passphrase)

def make_unencrypted_wallet(root_key, date):
    """
    make_unencrypted_wallet(root_key, date)
    Create a wallet with no encryption.
    Root key is a 16/32/64 byte BIP0032 key. Date is a 16 bit integer, per the spec.
    """
    prefix = {16: 0x28C1, 32: 0x4AC5, 64: 0xFBB3}[len(root_key)]
    checksum = crypto.secret_checksum(root_key)[0:4]

    byte_prefix = chr((prefix >> 8) & 0xFF) + chr(prefix & 0xFF)
    byte_date = chr(date & 0xFF) + chr((date >> 8) & 0xFF)

    return byte_prefix+byte_date+checksum+root_key

# Each encrypted wallet has a 2/3/4 byte "entropy" field that holds a salt and the KDF type
def make_wallet_entropy(entropy_length, kdf_type, entropy = None):
    """
    make_wallet_entropy(entropy_length, kdf_type, entropy = None)
    Used as a salt for wallet encryption, and also used to store the KDF type.
    entropy_length is the amount of entropy to return (in bytes).
    kdf_type is the KDF index, per the spec
    entropy is an optional field. If it is left as None, random entropy will be generated.
    Returns entropy_length bytes of entropy, with the KDF encoded in.
    """
    entropy = entropy or list(os.urandom(entropy_length)) # If the user hasn't specified entropy, get some
    entropy[0] = chr((ord(entropy[0]) & 0x7) | (kdf_type << 3)) # Insert the KDF type in the top 5 bits of "entropy"
    return ''.join(entropy)

def make_encrypted_wallet(root_key, date, kdf_type, passphrase, fake_passphrase = None):
    """
    make_encrypted_wallet(root_key, date, kdf_type, passphrase, fake_passphrase = None)
    root_key is the 16/32/64 byte BIP0032 key.
    date is the 16 bit integer date code.
    kdf_type is the KDF index, per the spec.
    passphrase is the "true" passphrase that the user intends to decrypt the wallet with
    fake_passphrase is a secondary passphrase that will also successfully decrypt the wallet,
       but will return a different key. Good for plausible deniability.
    Returns a byte string containing the wallet.
    """
    prefix, entropy_len = {16: (0xF83F,2), 32: (0x6731,3), 64: (0x4EB4,4)}[len(root_key)]
    byte_prefix = chr((prefix >> 8) & 0xFF) + chr(prefix & 0xFF)
    byte_date = chr(date & 0xFF) + chr((date >> 8) & 0xFF)
    byte_entropy = make_wallet_entropy(entropy_len, kdf_type)

    salt = byte_prefix + byte_date + byte_entropy
    hash_function = crypto.kdf_functions[kdf_type]

    encrypted_root_key = encrypt_root_key(root_key, salt, passphrase, hash_function)
    
    fake_passphrase = fake_passphrase or os.urandom(16) # If the user hasn't specified a fake passphrase, make one
    fake_root_key = decrypt_root_key(encrypted_root_key, salt, fake_passphrase, hash_function)
    
    bloom_filter = crypto.bloom_filter([root_key, fake_root_key]) # Insert both the real and fake keys into the bloom filter

    return byte_prefix+byte_date+byte_entropy+bloom_filter+encrypted_root_key




