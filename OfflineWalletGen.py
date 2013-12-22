# Will Yager's implementation of the in-development encrypted hierarchical deterministic wallet spec
# You may need to pip install qrcode and base58.
import qrcode
import bip38v2
import os
import sys
import getpass
import base58
from datetime import date

# Returns 32 bytes of random data that yields a valid private key when
# run through the BIP 0032 key -> secret algorithm.
def generate_root_key():
    random_data = os.urandom(32)
    try:
        bip38v2.generate_master_secret(random_data) # Will throw an exception if this root key generates an invalid result. Happens very rarely, but can still happen.
    except Exception as e:
        return generate_root_key() # Try again.
    return random_data

# A test function to generate a simple encrypted wallet
def make_simple_wallet(root_key, passphrase, kdf_type=0):
    """
    make_simple_wallet(root_key, passphrase, kdf_type=0)
    root_key is a 32 byte string (because the prefix we're using in this
    function specifies a 32 byte string; other lengths are possible).
    passphrase is a string
    kdf_type is according to the spec for this BIP.
    """
    if len(root_key) != 32:
        raise Exception("Root key must be 32 bytes")
    prefix = 0x148217 # 32 byte 1-factor key
    prefix += kdf_type # Add the hash function ID to the prefix
    prefix = hex(prefix)[2:].decode('hex')
    weeks = (date.today() - date(2013, 1, 1)).days/7 - 1 # The -1 is to be safe
    hash_function = bip38v2.generate_hash_function(kdf_type)
    return bip38v2.encrypt_root_key(prefix, weeks, root_key, hash_function, passphrase)

def generate_new_wallet():
    root_key = generate_root_key()
    if "--passphrase" in sys.argv:
        i = sys.argv.index("--passphrase") + 1
        passphrase = sys.argv[i]
    else:
        print "Please enter your passphrase. DO NOT FORGET THIS."
        passphrase = getpass.getpass("Passphrase:") 
        passphrase_confirm = getpass.getpass("Confirm:")
        if passphrase != passphrase_confirm:
            raise Exception("Password mismatch")
    encrypted_root_key = make_simple_wallet(root_key, passphrase, kdf_type=0)
    base58_text = base58.b58encode_check(encrypted_root_key)
    print "Encrypted wallet: " + base58_text
    qr_code = qrcode.make(base58_text)
    qr_code.save("wallet.png")
    print "QR code saved to wallet.png"

def decrypt_wallet():
    if "--wallet" in sys.argv:
        i = sys.argv.index("--wallet") + 1
        wallet = sys.argv[i]
    else:
        print "Please enter your encrypted wallet."
        wallet = raw_input("Wallet:")
    if "--passphrase" in sys.argv:
        i = sys.argv.index("--passphrase") + 1
        passphrase = sys.argv[i]
    else:
        print "Please enter your passphrase."
        passphrase = getpass.getpass("Passphrase:") 
    wallet_data = base58.b58decode_check(wallet)
    root_key = bip38v2.decrypt_root_key(wallet_data, passphrase)[3]
    print "Root key:"
    print root_key.encode('hex')

if __name__ == '__main__':
    if "--decrypt" in sys.argv:
        decrypt_wallet()
    elif "--create" in sys.argv:
        generate_new_wallet()
    else:
        print """
        Usage:
        --decrypt to decrypt a wallet code.
        --create to generate a new encrypted wallet
        --passphrase to specify a passphrase on the command line
        --wallet to specify a base58_check encoded encrypted wallet value
        if neither passphrase nor wallet are provided in the arguments,
        the user will be prompted for their values.
        """
