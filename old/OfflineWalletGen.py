# Will Yager's implementation of the in-development encrypted hierarchical deterministic wallet spec
# https://github.com/wyager/Encrypted-HD-wallet

import bip38v2
import os
import sys
import getpass
import base58
import crypto
from datetime import date

# Example of how to make a wallet
# Please run OfflineWalletGen.py from the command line if you 
# actually want to make a wallet
def simple_wallet():
    # root_key basically just needs to be a random 16/32/64 byte string.
    # It is used to derive all the addresses in the wallet.
    # This function is guaranteed to return a valid root key.
    root_key = bip38v2.generate_root_key(length=32)
    # Both real_passphrase and fake_passphrase will successfully decrypt the wallet.
    # However, each passphrase results in a different set of Bitcoin addresses.
    # The idea is that, if you are forced to decrypt your wallet by someone robbing you,
    # you just use the "fake" password. You can put a small amount of BTC in the "fake"
    # wallet, so that the person robbing you thinks it's your real wallet.
    # If the passphrase is set to None, the wallet will be unencrypted.
    real_passphrase = "ItsMyMoneyAndIWantItNow"
    fake_passphrase = "GoodLuckTakingMyMoney"
    # The "date" field tells wallet software when the wallet was created (by week)
    # so that the wallet knows when to start looking. If you don't want to reveal
    # the creation date, you can set this to zero (but it may hurt wallet performance)
    weeks = (date.today() - date(2013, 1, 1)).days/7
    # The KDF is the "Key Derivation Formula". This forumla is used to make the
    # wallet encryption/decryption take a lot longer, so it takes longer for a hacker
    # to guess the wallet password. The spec supports a number of KDFs. These are:
    # 0) Scrypt, weak. 1) Scrypt, medium. 2) Scrypt, strong. 8) PBKDF2-HMAC-SHA512, weak.  
    # 9) PBKDF2-HMAC-SHA512, strong. See crypto.py for details.
    # Scrypt is thought to be more resistant to attack by well-funded adversaries,
    # but is not as thoroughly vetted as PBKDF2-HMAC-SHA512, and also requires a lot of
    # RAM, so it's harder to run on mobile devices.
    kdf_type = 8 # Let's use PBKDF-HMAC-SHA512 with 2^16 iterations.
    # salt_entropy is called "entropy" in the spec. It's some extra random data
    # included with the wallet to make it harder for hackers to crack wallets en masse.
    # If we set entropy to None, or don't provide it as an argument, it will be randomly
    # generated. We need to provide at least 4 bytes if we choose to provide it.
    salt_entropy = os.urandom(4)

    # Now let's actually make the wallet
    wallet = bip38v2.make_wallet(root_key, weeks, passphrase=real_passphrase, fake_passphrase=fake_passphrase, kdf_type=kdf_type, salt_entropy=salt_entropy)
    # These are also valid ways to make wallets:
    if False:
        wallet2 = bip38v2.make_wallet(root_key, weeks) # unencrypted
        wallet3 = bip38v2.make_wallet(root_key, 0, passphrase = "bob") # No date, random fake password, default KDF (weaker scrypt)
        wallet4 = bip38v2.make_wallet(root_key, weeks, passphrase="hello", kdf_type=8) # Random fake password, weaker PBKDF2 as KDF

    # Now we'll encode the wallet in the format we're used to
    base58_wallet = base58.b58encode_check(wallet)

    # And display it to the user
    print base58_wallet


def generate_new_wallet():
    ##########################
    if "--rootkey" in sys.argv:
        i = sys.argv.index("--rootkey") + 1
        root_key = sys.argv[i].decode('hex')
    else:
        root_key = bip38v2.generate_root_key(length=32) # Feel free to change this to 16 or 64
    ##########################
    if "--unencrypted" in sys.argv:
          passphrase = None
          fake_passphrase = None
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
        if "--no-fake-passphrase" in sys.argv:
            fake_passphrase = None
        elif "--fake-passphrase" in sys.argv:
            i = sys.argv.index("--fake-passphrase") + 1
            fake_passphrase = sys.argv[i]
        else:
            print "Please enter your second (fake) passphrase."
            print "This can be used if you are forced to decrypt the wallet."
            print "Leave this as empty if you don't want a fake passphrase."
            fake_passphrase = getpass.getpass("Fake Passphrase:") 
            if fake_passphrase is not "":
                fake_passphrase_confirm = getpass.getpass("Confirm:")
                if fake_passphrase != fake_passphrase_confirm:
                    raise Exception("Password mismatch")
            else:
                fake_passphrase = None
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
    print "Generating wallet. May take quite a while!"
    encrypted_wallet = bip38v2.make_wallet(root_key, weeks, passphrase=passphrase, fake_passphrase=fake_passphrase, kdf_type=kdf_type)
    base58_text = base58.b58encode_check(encrypted_wallet)
    print "Encrypted wallet: " + base58_text
    if "--qrcode" in sys.argv:
        import qrcode
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

    if wallet[0:2] == "RK": #Wallet is unencrypted
        passphrase = None
    elif "--passphrase" in sys.argv:
        i = sys.argv.index("--passphrase") + 1
        passphrase = sys.argv[i]
    else:
        print "Please enter your passphrase."
        passphrase = getpass.getpass("Passphrase:")

    wallet_data = base58.b58decode_check(wallet)
    root_key = bip38v2.decrypt_wallet(wallet_data, passphrase)[3]
    print "Root key:"
    print root_key.encode('hex')

if __name__ == '__main__':
    if "--decrypt" in sys.argv:
        decrypt_wallet()
    elif "--create" in sys.argv:
        generate_new_wallet()
    elif "--test" in sys.argv:
        import tests
        tests.test()
    elif "--maketests" in sys.argv:
        import tests
        vectors = tests.make_tests()
        tests.pretty_print_vectors(vectors)
    else:
        print """
        Usage:
        Commands:
            --decrypt to decrypt a wallet code.
            --create to generate a new encrypted wallet
        Options:
            --unencrypted to make the new wallet unencrypted (default: encrypted)
            --passphrase to specify a passphrase on the command line (default: prompt user)
            --fake-passphrase to specify a fake passphrase (default: prompt user)
            --wallet to specify a base58_check encoded encrypted wallet value  (default: prompt user)
            --rootkey to specify a hex encoded root key for encryption (default: random)
            --weeks to specify a date, in weeks, since 2013-01-01 to use as the creation date (default: today)
            --kdf to specify the key derivation algorithm. 0/1/2 are scrypt. 8/9 are PBKDF2-HMAC-SHA512 (default: 0)
            --qrcode to generate a QR code (default: don't)
            --no-fake-passphrase if you don't want a fake passphrase (default: use a fake passphrase)
        Testing:
            --test to run test vectors
            --maketests to generate test vectors
        if neither passphrase nor wallet are provided in the arguments,
        the user will be prompted for their values.
        """

