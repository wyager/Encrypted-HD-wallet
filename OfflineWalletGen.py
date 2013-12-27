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

test_vectors = [
{
    'root key':"000102030405060708090a0b0c0d0e0f"
    ,'creation date':"24-12-2013"
    ,'clear':"WS1A3xqGKyHq4XMvq2Qj8xBu135p7AhSVSY4fqN"
    ,'password':"Satoshi"
    ,'kdf0':"ws19GjxzzP3vEBNp9jCcW3a7L8j3GQpdCkxBguL"
    ,'kdf1':"ws1H7QHFD9SKtqPEYhwG4Ty1TJrmY9PpeswoDLZ"
    ,'kdf2':"ws1Qx4bVRupdZyw9WvAfMAsiGrek42PPTJ3UeVo"
},
{
    'root key':"7f0ad7d595be13e6fe4cf1fa0fbb6ae9c26c5d9b09920709414982b6363d5844"
    ,'creation date':"24-12-2013"
    ,'clear':"WS13D1hB7v7XUYz9YH1u4UHab52MbmDUQSczJ7xavcJYkYiKvWnWa8CV87v1n"
    ,'password':"Nakamoto"
    ,'kdf0':"ws122WLGmSa7RPS6NSxWbSCbPGRsDigg8KuVNDtwPysozeJPTTQsjc6HV5FDV"
    ,'kdf1':"ws16JK3uHmQvTvJPxzTV7RJgXnsevMiyYUa443zi8jTpDDQAmRYRynf1V332F"
    ,'kdf2':"ws1Aa7mXp6FjxAxWbLbkvXpzj3ogwxo2veR6qs5jiA2CPt646dbdsedR9gZ3m"
},
{
    'root key':"fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
    ,'creation date':"24-12-2013"
    ,'clear':"WS1k2JRUKEaUCkqtiVcHHx5JBRiwCxU7LazRh2hREFsFkSrMqmLbEHuGb4DZXzr8Ro4WcVaJBZHesA5PyZuMnPxW1UCc1VK4gMwVfS7x"
    ,'password':"Vires In Numeris"
    ,'kdf0':"ws2AxUpnu8p8sboukkc1PRJrp1pYNNAnvn4A5ZbySxoJKxWy4L12vPJM8nyF2Jd3f6eanSqEij1mZyLhG9oW5G2DCLseRX5ucAohsz6d"
    ,'kdf1':"ws3Sa4zAotc76fFq3fKmaC8ALVDPPghYnhxiRFn8UuYHjCFND96Tp3ipW6ehA4YWQjTdiUVPpLtm62cpUy9EdVjsjmwZGfhbebPCiQvT"
    ,'kdf2':"ws4iBf9YieQDJVMSpeNkvnhy9MsVac3obtFyBtPhiUsviFhG29S7UhCLmXo52s7rHPx3W4v9HgT9d6rVYNGQJg1zGroHY1NnFjZ85UMH"
},
{
    'root key':"6ca4a27ac660c683340f59353b1375a9"
    ,'creation date':"24-12-2013"
    ,'clear':"WS1A3y1yzdgNW2BgegrtNNV57EsaMdEvYqdyWFs"
    ,'password': u'\u8061\u4e2d\u672c'
    ,'kdf0':"ws19Gk9if3SS37cqedG3dTSNgRPRSH9cf6qxarB"
    ,'kdf1':"ws1H7QTxsopohhHTPE3RXAhWpFUWW9kEKvrhUq3"
    ,'kdf2':"ws1Qx4nD6aDA4E29tMF6o8AsZgqmPpSyxskQMFn"
}
]



b58 = lambda data : base58.b58encode_check(data)
b58d = lambda data: base58.b58decode_check(data)
def test():
    for i in range(len(test_vectors)):
        print "Testing vector %i..." % (i+1)
        v = test_vectors[i]
        root = v['root key'].decode('hex')
        day, month, year = tuple(map(int, v['creation date'].split('-')))
        weeks = (date(year, month, day) - date(2013, 1, 1)).days/7
        if v['clear'] != b58(bip38v2.make_wallet(root, weeks, passphrase = None)):
            print "Error: On vector %i, the cleartext wallet is different." % (i+1)
            print v['clear']
            print b58(bip38v2.make_wallet(root, weeks, passphrase = None))
        else:
            print "clear OK"
        if v['kdf0'] != b58(bip38v2.make_wallet(root, weeks, passphrase = v['password'], kdf_type=0)):
            print "Error: On vector %i, the kdf0 wallet is different." % (i+1)
        else:
            print "kdf0 OK"
        if v['kdf1'] != b58(bip38v2.make_wallet(root, weeks, passphrase = v['password'], kdf_type=1)):
            print "Error: On vector %i, the kdf1 wallet is different." % (i+1)
        else:
            print "kdf1 OK"
        if v['kdf2'] != b58(bip38v2.make_wallet(root, weeks, passphrase = v['password'], kdf_type=2)):
            print "Error: On vector %i, the kdf2 wallet is different." % (i+1)
        else:
            print "kdf2 OK"
        recovered_root = bip38v2.decrypt_root_key(b58d(v['clear']))[3]
        if recovered_root == root:
            print "Decrypted wallet OK (clear)"
        else:
            print "Error decrypting wallet (clear)"
        recovered_root = bip38v2.decrypt_root_key(b58d(v['kdf0']), v['password'])[3]
        if recovered_root == root:
            print "Decrypted wallet OK (kdf0)"
        else:
            print "Error decrypting wallet (kdf0)"
        recovered_root = bip38v2.decrypt_root_key(b58d(v['kdf1']), v['password'])[3]
        if recovered_root == root:
            print "Decrypted wallet OK (kdf1)"
        else:
            print "Error decrypting wallet (kdf1)"
        recovered_root = bip38v2.decrypt_root_key(b58d(v['kdf2']), v['password'])[3]
        if recovered_root == root:
            print "Decrypted wallet OK (kdf2)"
        else:
            print "Error decrypting wallet (kdf2)"



if __name__ == '__main__':
    if "--decrypt" in sys.argv:
        decrypt_wallet()
    elif "--create" in sys.argv:
        generate_new_wallet()
    elif "--test" in sys.argv:
        test()
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

