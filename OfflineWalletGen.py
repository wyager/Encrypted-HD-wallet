# Will Yager's implementation of the in-development encrypted hierarchical deterministic wallet spec
# You may need to pip install qrcode and base58.
import qrcode
import bip38v2
import os
import sys
import getpass
import base58
from datetime import date


# A test function to generate a simple encrypted wallet
def make_simple_wallet(passphrase):
    """
    make_simple_wallet(root_key, passphrase, kdf_type=0)
    passphrase is a string
    kdf_type is according to the spec for this BIP.
    """
    root_key = bip38v2.generate_root_key()
    
    return 

def generate_new_wallet():
      ##########################
    if "--rootkey" in sys.argv:
        i = sys.argv.index("--rootkey") + 1
        root_key = sys.argv[i].decode('hex')
    else:
        root_key = bip38v2.generate_root_key()
      ##########################
    if "--unencrypted" in sys.argv:
          passphrase = None
    else:
        if "--passphrase" in sys.argv:
            i = sys.argv.index("--passphrase") + 1
            passphrase = sys.argv[i]
        else:
            print "Please enter your passphrase. DO NOT FORGET THIS."
            passphrase = getpass.getpass("Passphrase:") 
            passphrase_confirm = getpass.getpass("Confirm:")
            if passphrase != passphrase_confirm:
                raise Exception("Password mismatch")
      ##########################
    if "--weeks" in sys.argv:
        i = sys.argv.index("--weeks") + 1
        weeks = int(sys.argv[i])
    else:
        weeks = (date.today() - date(2013, 1, 1)).days/7
    ##########################
    if "--kdf" in sys.argv:
        i = sys.argv.index("--kdf") + 1
        kdf_type = int(sys.argv[i])
    else:
        kdf_type = 0
    ##########################
    encrypted_wallet = bip38v2.make_wallet(root_key, weeks, passphrase=passphrase, kdf_type=kdf_type)
    base58_text = base58.b58encode_check(encrypted_wallet)
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

    if wallet[0:2] == "WS": #Wallet is unencrypted
        passphrase = None
    elif "--passphrase" in sys.argv:
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
        --unencrypted to make the new wallet unencrypted
        --passphrase to specify a passphrase on the command line
        --wallet to specify a base58_check encoded encrypted wallet value
        --rootkey to specify a hex encoded root key for encryption
        --weeks to specify a date, in weeks, since 2013-01-01 to use as the creation date
        --kdf to specify the key derivation algorithm. 0 is weakest/fastest, and the default. 2 is max.
        --test to run test vectors
        if neither passphrase nor wallet are provided in the arguments,
        the user will be prompted for their values.
        """


