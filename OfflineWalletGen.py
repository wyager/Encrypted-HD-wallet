# Will Yager's implementation of the in-development encrypted hierarchical deterministic wallet spec
# You may need to pip install qrcode and base58.
import qrcode
import bip38v2
import os
import sys
import getpass
import base58
import crypto
from datetime import date


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
        passphrase = passphrase.encode('utf8')
        if "--random-fake-passphrase" in sys.argv:
            fake_passphrase = None
        elif "--fake-passphrase" in sys.argv:
            i = sys.argv.index("--passphrase") + 1
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
    encrypted_wallet = bip38v2.make_wallet(root_key, weeks, passphrase=passphrase, fake_passphrase=fake_passphrase, kdf_type=kdf_type)
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
        passphrase = sys.argv[i].encode('utf8')
    else:
        print "Please enter your passphrase."
        passphrase = getpass.getpass("Passphrase:").encode('utf8')

    wallet_data = base58.b58decode_check(wallet)
    root_key = bip38v2.decrypt_wallet(wallet_data, passphrase)[3]
    print "Root key:"
    print root_key.encode('hex')

test_vectors = [
{
'root key': '000102030405060708090a0b0c0d0e0f', 
'creation date': '04-02-2014', 
'clear': 'RK6nEaou4eFQC4SfrHtdh9jpnEme4K9dt2jBmG', 
'password': 'Satoshi', 
'privkey': 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi', 
'fake_password': 'Alpaca', 
'kdf0': 'rk354bXH1JsXTwWmuvRskFWoeUX8hMjQiseNM7wj6', 
'privkey0': 'xprv9s21ZrQH143K3TxQaa6hd8mPR9Bw2ue1H5TMjUYuUEPEDUTxK7PZ191poMob8zbU5hsckCQoBFYtQZzbgxtYz1acbLmFQtjcbWSYhQ7kSZE', 
'kdf1': 'rk354bq4dXW8VB67XSZzQdVLFJFz64v1Dh1i12VTY', 
'privkey1': 'xprv9s21ZrQH143K4JxBYKwi5dGE59G4vtRGLiyinEPxMdgYdPe6UqMrgJneacME8JQuoskvEzEZ1vnHwW8i1h4Mwm5wj5BUPJWf764QfkkvFAQ', 
'kdf8': 'rk354dUN5yrKvrMQRneKJvdJFf77WDJw5ZfeeRt4H', 
'privkey8': 'xprv9s21ZrQH143K2AaodGyHvDBQFrFcDdHVJj15zqJUkU1wuLS5kFxgE9rGBvh8rAUeenfhhwC91efxn8kHbhKGeTaQkkyGFvbKiAuLcx8t8qP', 
'kdf9': 'rk354dedikaytYJ7D4btpcVfGuakfixf5yj2SnTcX', 
'privkey9': 'xprv9s21ZrQH143K3Xt1wRGXFZ6D76dGLyGTWxvPv1QhkRcyPCbi6kM7WJG9dH6X9UMmzoTwoix3BsnzKf7ZkkpinPw8hyGaNLWzmcbemJVUWTj', 
},
{
'root key': '7f0ad7d595be13e6fe4cf1fa0fbb6ae9c26c5d9b09920709414982b6363d5844', 
'creation date': '04-02-2014', 
'clear': 'RK22qqMb3CozsQfTTbSVsLEgXcjekut99SuSHn6urU4vWxjiQneHWVYabWgv', 
'password': 'Nakamoto', 
'privkey': 'xprv9s21ZrQH143K3f9hMVvcbY4EX4CfxsEtc6C5BMkZtgGpTGpxAscoq7SLSAcL6k5dxaZ9s4SChrtfSFoKpijuwAnhuPn76eva6W8bDr118t3', 
'fake_password': 'hunter2', 
'kdf0': 'rk2cMHki73WbrYgo7XK9kSr6CGBPsMjU3uZf3f3qxCv4QoGy63DkBoGJKhPdvUtp', 
'privkey0': 'xprv9s21ZrQH143K2dojoDyxmK7SLnyqSvn56oysqu2Ctf24Rdux6JFLReRgcH5KAM1GxCTVxjpc13Mh18kSmYqUep5EkbDvQJfEEVeLZXhyuYj', 
'kdf1': 'rk2cMJ1KizRTPbBv8zaECpcQEY66SiZcfM2yAuCpdjDbJsdgZu9xdoFDpGuTVRYe', 
'privkey1': 'xprv9s21ZrQH143K35ajB7SFjQJAzrmGbAJyp7iBYxhB3DcY9CC8XW5GkAHXDe2HXG6hUS3iquPbGAPuZygXm43BgYamWxiDN5sFm7w12db4uvU', 
'kdf8': 'rk2cMNSiQsAATQ19Y12nhGuL2uksZVASxNXAdjqrU3KaVcLH71No442sH1YvcwDL', 
'privkey8': 'xprv9s21ZrQH143K3aA9djUAAX1ASAcdqtuHEXmypDNd8gNy5PH4nm7y4QrieVdw7iQgA46LCJJAxdcN4qrP87Tp8XzJQbw7aeH3LPK8G7Zj6YT', 
'kdf9': 'rk2cMPALytexkDuxm6QREojvgzoKcgKNeURPXDTVzPdZmbfzM2R3RX75Qqu4Yk5r', 
'privkey9': 'xprv9s21ZrQH143K4X6wJWAQbDawhqb2DaQT7mjbPhqNBHmspzrD1J5kcnb5syHr9LQggN3PtmvkjbMVs4zgTyjWmqKS4ix7J92z59cvbkF5W1s', 
},
{
'root key': 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542', 
'creation date': '04-02-2014', 
'clear': 'RK2BvY13FUD6bX25tA7XDyfAn7zbXSL8pR6TRE3EHZZ8qBm9qEyZRih8x1XhhcZwjcTfpe1Qjydn4KUdia8Wf1NshUusP1D38i88MLU9', 
'password': 'Vires In Numeris', 
'privkey': 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U', 
'fake_password': 'Quis Custodiet Ipsos Custodes?', 
'kdf0': 'rk5ySVmNtFzgWZFXAehk6Akvf5PanApA5Y12arynxXZF7Lhc1YqaudukJFngEBXkpc4RGqqkM3ZW4RjE7HwhWTB5Uxi7pXy7vuKouQuZZzoTP', 
'privkey0': 'xprv9s21ZrQH143K4PUz4iSDMmUE9uovNGnZE6jZdKPDqozk8nBHBk3FRXo3tJEt4TFfo7Tkhnc9TAzUFvg7hsg7M1SddHF6nX9bBw9Tn968Aki', 
'kdf1': 'rk5ySWZriEipJWKyL6X8Rd86cgKn9qgGC7C4QYLVCjhyuBZiKXezzf6vjyJBXtFmP1f4qzaAAP5baRhKP4yCGo6LAU9keJCvRXoU77SUNmg1o', 
'privkey1': 'xprv9s21ZrQH143K4KmLN9WLjPsVmKgVXPUfAScqkGeifQpTeXFw2X4ijfWNMDMtu4qfbbHZ69VSLcCMiGLHSLaQQY7Rb3PzHMRLLqVN6mjrGHP', 
'kdf8': 'rk5ySbwggFoh8MZ1CnxqSeKwzag9ifrECtToowiRYKRgcueyMGX39yBGwxbY7ExKeTSmCRHokToThN8pxYWA9WQKrouVuatCMjcvX8PZ16tPf', 
'privkey8': 'xprv9s21ZrQH143K3CHptaD7aNZBUAYhjmCe5ceDLttwqKoQ3F73DRHNrSAVphAX2okZDWK82Eznf4bpmv9qjHZ7nzQjv2qNqXV8YwCWQEw2jiA', 
'kdf9': 'rk5ySd2iHrVJ1CZ86Pyt6zerNzzBHfZo2rcBAX4MKNzX7doCZnNpBMc3pPf6igTCnk796isqtaEdcfagrN8Pced9VAtENVBtpugBLnjiGd28h', 
'privkey9': 'xprv9s21ZrQH143K3YMD7T6LoFVGttrMKj9jxGAxfCv3pv6ZQfWcuBV5pqdcjyooGrqa8NeraYUuiTWJSWuz4fVMiCuEK8tWggZ6yMZZK7xLBkx', 
},
{
'root key': '6ca4a27ac660c683340f59353b1375a9', 
'creation date': '04-02-2014', 
'clear': 'RK6nEmXZj2nqgtCVWk3s7Suvz2XtWrdhDPpJqS', 
'password': '\xe8\x81\xa1\xe4\xb8\xad\xe6\x9c\xac',
'privkey': 'xprv9s21ZrQH143K3mJ4upPSDfXdA34yNjem6PSsXT63vm8dq8ikUJv4iiTD3PrSKtdGZXFVD689z5T7knXo55BjcHS2WL3Syp2DbGgnbgxw2QA', 
'fake_password': 'Bitcoin', 
'kdf0': 'rk354bYQBax15mmBSLTpaVuLRb9nDuaVbEseqBWpG', 
'privkey0': 'xprv9s21ZrQH143K3BMoPfivq74do9mxCnKRTZHWScTvVyrxGtCNvGd8bCZJk1Npwnds3ghiy4TTwmwtbSkpzTFcqLup57AWqm3NvRr6sNs7ZVt', 
'kdf1': 'rk354bi6JiGeb5suvydsNtTosocEbpWcjoK7VL9Xv', 
'privkey1': 'xprv9s21ZrQH143K2Su2mQR7u6pweA8kwv4y3bKkvUeJUanC4eT7VVp64VxNH5uzwY12wE315rZMMf5XJQLcNLPBF7zcgoFv29UM3R9ctDqdshr', 
'kdf8': 'rk354dLtDHN3mPNSFABTNrhKmweKPZ55LJ31EM3k6', 
'privkey8': 'xprv9s21ZrQH143K43FPi9awkCScXaAY4mEJje4PhS5uk2R67QU6p7bHXbvwgRdcwU9xZozYZ9hqfjm6ccAbGgU5eN4fp7uMY59MGq8swJVQPKW', 
'kdf9': 'rk354diEYQb4EdNjyosAZGNAB8L1spefWdz7RmZfX', 
'privkey9': 'xprv9s21ZrQH143K2stwSFWe4rPabNH1k1EVwQKwr7poayVZNPJup716aWVjDBVRVRh8gSgZhTP4uiaNuCkFbXXJCbDSnmvwNbnCuvQqHDDj7Ew', 
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
        password = v['password']
        fake_password = v['fake_password']

        ###### Clear ######
        if v['clear'] != b58(bip38v2.make_wallet(root, weeks, passphrase = None)):
            print "Error: On vector %i, the cleartext wallet is different." % (i+1)
            print v['clear']
            print b58(bip38v2.make_wallet(root, weeks, passphrase = None))
        else:
            print "clear OK"

        recovered_root = bip38v2.decrypt_wallet(b58d(v['clear']))[3]
        if recovered_root == root:
            print "Decrypted wallet OK (clear)"
        else:
            print "Error decrypting wallet (clear)"

        ###### Encrypted ######
        for kdf in (0,1,8):
            # if v['kdf'+str(kdf)] != b58(bip38v2.make_wallet(root, weeks, passphrase = password, kdf_type=kdf)):
            #     print "Error: On vector %i, the kdf0 wallet is different." % (i+1)
            # else:
            #     print "kdf0 OK"
            recovered_root = bip38v2.decrypt_wallet(b58d(v['kdf'+str(kdf)]), passphrase=password)[3]
            if recovered_root == root:
                print "Decrypted wallet OK (kdf{})".format(kdf)
            else:
                print "Error decrypting wallet (kdf{})".format(kdf)
            recovered_fake_root = bip38v2.decrypt_wallet(b58d(v['kdf'+str(kdf)]), passphrase=fake_password)[3]
            recovered_fake_master = crypto.generate_master_secret(recovered_fake_root)
            if recovered_fake_master == b58d(v['privkey'+str(kdf)])[-32:]:
                print "Decrypted wallet w/fake password OK (kdf{})".format(kdf)
            else:
                print "Error decrypting wallet with fake password (kdf{})".format(kdf)


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
        --fake-passphrase to specify a fake passphrase
        --random-fake-passphrase to specify a random fake passphrase
        --wallet to specify a base58_check encoded encrypted wallet value
        --rootkey to specify a hex encoded root key for encryption
        --weeks to specify a date, in weeks, since 2013-01-01 to use as the creation date
        --kdf to specify the key derivation algorithm. 0/1/2 are scrypt. 8/9 are PBKDF2-HMAC-SHA512
        --test to run test vectors
        if neither passphrase nor wallet are provided in the arguments,
        the user will be prompted for their values.
        """

