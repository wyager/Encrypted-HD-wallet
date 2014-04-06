# Will Yager's implementation of the in-development encrypted hierarchical deterministic wallet spec
# https://github.com/wyager/Encrypted-HD-wallet

import bip38v2
import base58
import crypto
from datetime import date

b58 = lambda data : base58.b58encode_check(data)
b58d = lambda data: base58.b58decode_check(data)

# root key: the random seed for the entire BIP 0032 wallet
# privkey: the private key that is the result of the BIP 0032 derivation of the Root key
# creation date: the date on which the wallet was generated
# clear: the no-password, non-encrypted version of the wallet
# password: the password used to encrypt the wallet
# salt_entropy: the random data used as the salt. If your implementation allows specifying this random data,
#   you can use it to check deterministically if you generate the same result as the reference implementation.
# fake_password: the secondary password which will also work, but will decrypt to a completely different wallet
# kdfn: the wallet, as encrypted with the kdf with ID n (see crypto.py, "kdf_functions")
# fake_privkeyn: the Private key that you get when you decrypt the wallet with the fake password.
#   This is different for each KDF. Remember, this is the Private key, not the Root key. You have to
#   get the Root key first, then use that to calculate the private key.

test_vectors = [
{
"root key" : "000102030405060708090a0b0c0d0e0f",
"privkey" : "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
"creation date" : "04-02-2014",
"clear" : "RK6nEaou4eFQC4SfrHtdh9jpnEme4K9dt2jBmG",
"password" : "Satoshi",
"fake_password" : "Alpaca",
"salt_entropy" : "abcd",
"kdf0" : "rk354bQrcjkYRANhWiMLWXEmvnNHw4EFK66MnxPCU",
"fake_privkey0" : "630dd571ceeaeedc1c35fc76b289dbbe58a2b4e910b27b621ac0250f9524b3c5",
"kdf1" : "rk354bf4hZffyayxAAJ5bPJYGKnU1Ewch7NAhXGdb",
"fake_privkey1" : "f9a2b0312d7443d46da7969da9ddd54be3ecf6853595f6311672defabb583bb6",
"kdf8" : "rk354dNXJrN5ubGafWCRsGkdYamR4S2GcgdE4kzAh",
"fake_privkey8" : "e4c8ab76869913eb4484b6b6c67236613c714c6b656ab84d14fd662dfb6c2774",
"kdf9" : "rk354dcjZADDucGEjothnKhNPdu3RMjs1XWUKdYrt",
"fake_privkey9" : "fb7f2a443bb1f868ef91050c4f58a39ef58b59e274198f1fbce8a6556f892447",
},
{
"root key" : "7f0ad7d595be13e6fe4cf1fa0fbb6ae9c26c5d9b09920709414982b6363d5844",
"privkey" : "08965cb883e1c8783d72b65a0b7104d64baa9412eb655a6f05c5aaa6103781be",
"creation date" : "04-02-2014",
"clear" : "RK22qqMb3CozsQfTTbSVsLEgXcjekut99SuSHn6urU4vWxjiQneHWVYabWgv",
"password" : "Nakamoto",
"fake_password" : "hunter2",
"salt_entropy" : "defg",
"kdf0" : "rk2cMHcqyGnhKuDNjXUWkNeiBpThPjfDrFkdHJ3xksXEnUABUJzUCKYpcoCGPdZB",
"fake_privkey0" : "be888d1aacda7131f950f5c10192495158d622458cd06a1863f74313a090f91e",
"kdf1" : "rk2cMJD2QzEDEkZMUEjj5NcmoZBie6Y4BYEmL6jE6oqfuaTuijPneK9dYm7wTzTS",
"fake_privkey1" : "417d240196d8c9107bc4c78da4a15d85d5c598ecf1f0c4fac7fe72492cad2378",
"kdf8" : "rk2cMNLHXJVqruEEQmVnuqeT7Lmdb5bwSXc9xJxS97UV22BiiQu9w14fRAra1fu3",
"fake_privkey8" : "7e0860f36df848e403779e881f7a9a902686c96cb462ac08a019c393203e285d",
"kdf9" : "rk2cMNvTxtbH45rT9c6oqBvEapPoQmjprvbVaP46KamkZmRbCJ8LthrBU7CJxwNQ",
"fake_privkey9" : "a5046c82c9b218f462dac4b64de04d8fb9a823bf9609531ea5a73d527da67169",
},
{
"root key" : "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
"privkey" : "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
"creation date" : "04-02-2014",
"clear" : "RK2BvY13FUD6bX25tA7XDyfAn7zbXSL8pR6TRE3EHZZ8qBm9qEyZRih8x1XhhcZwjcTfpe1Qjydn4KUdia8Wf1NshUusP1D38i88MLU9",
"password" : "Vires In Numeris",
"fake_password" : "Quis Custodiet Ipsos Custodes?",
"salt_entropy" : "hijk",
"kdf0" : "rk5ySVNYwdRPRMXXhKgu25U6wJp9t3c4P1r2zXga16JMeA9GzyXm8ctyJX6jhny4crfrrJTHzs67zQDwYCj19vWDW3j4JyRJEywVcFBv11TqH",
"fake_privkey0" : "8e7b6fecf939ed5302ea44b846e7d3f46a4f93c5530cd87109d2af5831c61751",
"kdf1" : "rk5ySW9NGHhFojnidy9CodAvVAu35dLCRvDo5iNdzRcECuKkEPoPRTHZ6cBvn5D7GNsNMGy2iTgTPQvf93UNVuLqRaz3PRRrvkBngDWQNrvP9",
"fake_privkey1" : "0226978f39c2c56fbad94f188da85de5d267217335c2c57f835523883f9312f8",
"kdf8" : "rk5ySbZ5WuWGMfk2F9CMmHYjHdjP5T1owDuLyFkQjwdyT2Xzt7NknHWYHfret8YGp4iDxNcmEtSYg92A3R9kmJH8B4VnFx275mZTip9p5XLqc",
"fake_privkey8" : "020d162fb855a5787a9cfd532c241b36233990cb912ee322a6346d4ebc4ab201",
"kdf9" : "rk5yScKtqZmN4mX5fMy1BUGg2KEpM7r36T7aLRVK6aECKBhoMfv1aS5jobFciWRLUNzUayKcy9FrdQ8CRspLhbKSr5haVEmogr1iTMb1fZwip",
"fake_privkey9" : "bbacaf72ceaa6d3886079cefcb6faf95e7b726da7be88d66db5784870c73b01e",
},
{
"root key" : "6ca4a27ac660c683340f59353b1375a9",
"privkey" : "f544dd076ffe8fb68aa81ca9a33059946e9a91f8d95258ae1b7a1db6215ce51a",
"creation date" : "04-02-2014",
"clear" : "RK6nEmXZj2nqgtCVWk3s7Suvz2XtWrdhDPpJqS",
"password" : "\xe8\x81\xa1\xe4\xb8\xad\xe6\x9c\xac",
"fake_password" : "Bitcoin",
"salt_entropy" : "lmno",
"kdf0" : "rk354bWG5cnRJFxd6AAvvsosBHdWkUB33vVSFboZG",
"fake_privkey0" : "2a9abc3294d74c40b34068661a6e3e0ceea1cec3fdd8ae428d70741374ab4d22",
"kdf1" : "rk354bkUMBiYmkboWJzG9hJv4JNnnB5Aa8jDs7Pkp",
"fake_privkey1" : "8cff085e82a9fc409da82adea468292f78e748fad753169628c29e31c8704186",
"kdf8" : "rk354dTvjDLPeSEWNcqWe9Yv4FCRRfsXsDyNBGpky",
"fake_privkey8" : "19bf0e1fd49072d35e1f97597a18978f7a4f340b265a2e61e1917cc3a1750c05",
"kdf9" : "rk354di8wPeBNUZX2AgknJ1uKBKLDdp4okPeVrAmF",
"fake_privkey9" : "820e347b37d373717f810d96be2f0fea90ee2a11bb50356deb26f42300ce2114",
}
]



test_templates = [
{
'root key' : '000102030405060708090a0b0c0d0e0f',
'creation date' : '04-02-2014',
'password' : 'Satoshi',
'fake_password' : 'Alpaca',
'salt_entropy' : "abcd"
},
{
'root key' : '7f0ad7d595be13e6fe4cf1fa0fbb6ae9c26c5d9b09920709414982b6363d5844',
'creation date' : '04-02-2014',
'password' : 'Nakamoto',
'fake_password' : 'hunter2',
'salt_entropy' : "defg"
},
{
'root key' : 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
'creation date' : '04-02-2014',
'password' : 'Vires In Numeris',
'fake_password' : 'Quis Custodiet Ipsos Custodes?',
'salt_entropy' : "hijk"
},
{
'root key' : '6ca4a27ac660c683340f59353b1375a9',
'creation date' : '04-02-2014',
'password' : '\xe8\x81\xa1\xe4\xb8\xad\xe6\x9c\xac',
'fake_password' : 'Bitcoin',
'salt_entropy' : "lmno"
},
]

# Given a template containing some basic info, deterministically generate all corresponding wallets
def test_from_template(template):
    vector = {key:template[key] for key in template}

    root_key, password, fake_password, salt_entropy = template['root key'].decode('hex'), template['password'], template['fake_password'], template['salt_entropy']
    day, month, year = map(int, template['creation date'].split('-'))
    creation_week = (date(year, month, day) - date(2013, 1, 1)).days/7

    vector['privkey'] = crypto.generate_master_secret(root_key).encode('hex')
    vector['clear'] = b58(bip38v2.make_wallet(root_key, creation_week))
    for kdf in (0,1,8,9):
        print kdf
        encrypted = bip38v2.make_wallet(root_key, creation_week, passphrase=password, fake_passphrase=fake_password, salt_entropy=salt_entropy, kdf_type=kdf)
        vector['kdf'+str(kdf)] = b58(encrypted)
        vector['fake_privkey'+str(kdf)] = crypto.generate_master_secret(bip38v2.decrypt_wallet(encrypted, passphrase=fake_password)[3]).encode('hex')
    return vector

# Create a set of tests based on test_templates
def make_tests():
    return [test_from_template(template) for template in test_templates]

# Run the various tests in test_vectors
def test():
    for i in range(len(test_vectors)):
        print "Testing vector %i..." % (i+1)
        v = test_vectors[i]
        root = v['root key'].decode('hex')
        day, month, year = map(int, v['creation date'].split('-'))
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
            if recovered_fake_master == v['fake_privkey'+str(kdf)].decode('hex'):
                print "Decrypted wallet w/fake password OK (kdf{})".format(kdf)
            else:
                print "Error decrypting wallet with fake password (kdf{})".format(kdf)
            generated_wallet = b58(bip38v2.make_wallet(root, weeks, passphrase=password, fake_passphrase=fake_password, salt_entropy=v['salt_entropy'], kdf_type=kdf))
            if generated_wallet == v['kdf'+str(kdf)]:
                print "Generated the same encrypted wallet with kdf " + str(kdf)
            else:
                print "Error generating the same encrypted wallet with kdf " + str(kdf)

# Print out the test vectors in nice, copy-pastable JSON
def pretty_print_vectors(vectors):
    for vector in vectors:
            print '{'
            for key in ['root key', 'privkey', 'creation date', 'clear', 'password', 'fake_password', 'salt_entropy', \
                 'kdf0', 'fake_privkey0', 'kdf1', 'fake_privkey1', 'kdf8', 'fake_privkey8', 'kdf9', 'fake_privkey9']:
                print """\'{}\' : \'{}\',""".format(key, vector[key])
            print '},'

