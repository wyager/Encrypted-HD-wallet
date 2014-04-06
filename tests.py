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
    "root key": "000102030405060708090a0b0c0d0e0f",
    "fake_password": "Alpaca",
    "salt_entropy": "abcd",
    "fake_privkey0": "6bcc037bd16310b5f77b23bf0cd5aa988e4b9a628b5ce0f06b629fa68e1c6e64",
    "kdf1": "rk354bf4g6L4A9GqHzMDHSYpyYSFAf7BomA6D6GpT",
    "password": "Satoshi",
    "privkey": "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35",
    "fake_privkey9": "ca5341e5026a608a1ef866adefd6f071a494941a17a6116700da975083589947",
    "kdf9": "rk354dcjNDdMEWsFynnuuabbiXz3yNmFr4pKiJHvy",
    "kdf8": "rk354dNXHJ3SnLL6xCErGcyAycgmv8Hv5PV8nMd1V",
    "creation date": "04-02-2014",
    "clear": "RK6nEaou4eFQC4SfrHtdh9jpnEme4K9dt2jBmG",
    "fake_privkey8": "b08dbcdb81066e7d1b55f09e10313882a544c4e76cbe0ebdddaae55ad730ddb3",
    "fake_privkey1": "737b0301592fed41d991e90e0f270f1a72d94322af67cf8434af78ce68291bdf",
    "kdf0": "rk354bQrjCW362gYMxtD8UMNT7qHG8Gd6nbGLQ5Yo"
  },
  {
    "root key": "7f0ad7d595be13e6fe4cf1fa0fbb6ae9c26c5d9b09920709414982b6363d5844",
    "fake_password": "hunter2",
    "salt_entropy": "defg",
    "fake_privkey0": "3bffaca5cf730f79425e63b2c7b248addac9085882857f6df1bc11ffec323bba",
    "kdf1": "rk2cMJD2R5CkvZVJoo82SDFsn5TTHec7XXRQ1qebDmH8pUPGKknkMW3a7VVAW4gn",
    "password": "Nakamoto",
    "privkey": "08965cb883e1c8783d72b65a0b7104d64baa9412eb655a6f05c5aaa6103781be",
    "fake_privkey9": "28ae3ff8d73ad4cd45c2b736a4e9f39c2ca7d69fb8a49563f90b7a19ad3addbf",
    "kdf9": "rk2cMNvTxxiZchSXYE3swrhr4nWpUXgCsfyptS5Ub1d7Mb3ejhcRPneduJDTRFmi",
    "kdf8": "rk2cMNLHXBHxxwzEjrSqf6Ah8GTVFWjZPe7KbFkQbXeSiVkqLtxVxJG1Q44xHmFY",
    "creation date": "04-02-2014",
    "clear": "RK22qqMb3CozsQfTTbSVsLEgXcjekut99SuSHn6urU4vWxjiQneHWVYabWgv",
    "fake_privkey8": "636dde6dc1ca4ab6941517e3a1068326f2466c4c921470b05520e3c0ef214290",
    "fake_privkey1": "6ddf29297d59a4a7a1978c56d696bdab71a591b5faa21fc63c96780be161a7be",
    "kdf0": "rk2cMHcqyGypVPFoH6nPtsULqpLX4hWZ238mbz51EDtHPT2qDwSrjpxSZr4hihFw"
  },
  {
    "root key": "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
    "fake_password": "Quis Custodiet Ipsos Custodes?",
    "salt_entropy": "hijk",
    "fake_privkey0": "3b72c9429efcbb2a16bfe76169a859c0b33059625bd990a87fcd4427e7fc635c",
    "kdf1": "rk5ySW9NGHgQnHSiKaZEc6NTLtDtgd6tnQxGMg9GK3xSP17RoFWthYWAtyjythbGkKicauGJzfnYNjpt72YXhfiCdNb6d3EsQk28Bxq2nQht1",
    "password": "Vires In Numeris",
    "privkey": "4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e",
    "fake_privkey9": "42ed0ee4353cd4e732fca0e33f707c823c555d13c7d84784ab852721fdc88bce",
    "kdf9": "rk5yScKtqZnAY2VzcyQ4hfqWQHqHAsVZarDkJ3soWXBhQjE4DRv8bSqBU2TP8VdxoxDeuwA3Y5JDenxFVeyoMxaavmKAumwkDXRMVdP7ZaVMe",
    "kdf8": "rk5ySbZ5WuWP8FFVtQiJooHbYTNMSDb7gpCvcjusRj4t7qQ6tRS1vTzrZxtk6hHy4WBVSucSAHh88w3ptNY8w89qtib8sxdCfWtohruFxnguR",
    "creation date": "04-02-2014",
    "clear": "RK2BvY13FUD6bX25tA7XDyfAn7zbXSL8pR6TRE3EHZZ8qBm9qEyZRih8x1XhhcZwjcTfpe1Qjydn4KUdia8Wf1NshUusP1D38i88MLU9",
    "fake_privkey8": "d5359d8ca155a6dd54cfa67a0fba5fd8b5d495c53e60a93cbb2be0223376c0a4",
    "fake_privkey1": "c8291c7b2ff3b7c3e7347b82676a1c700e50da865d8b4e0b5fce4547c7d9e1b0",
    "kdf0": "rk5ySVNYwdR3mfdeLrh6kVmEDQGifmUBzHqrXjcsNtu1Pqg9LnrgMCfwwdMi16GEuH5U2xEoELA1dcjeXxgMqcconb5SD9V2tKDY2cKwvUSGR"
  },
  {
    "root key": "6ca4a27ac660c683340f59353b1375a9",
    "fake_password": "Bitcoin",
    "salt_entropy": "lmno",
    "fake_privkey0": "5f401c7b45701834b27aee5140be1baa87cc47c36e984eb8685b93744074e200",
    "kdf1": "rk354bkULN8WjSVGcr4YEe3TTZ6FfiNJFDGA6kjU8",
    "password": "\u8061\u4e2d\u672c",
    "privkey": "f544dd076ffe8fb68aa81ca9a33059946e9a91f8d95258ae1b7a1db6215ce51a",
    "fake_privkey9": "e9b9e0aac6e21bcfb7697664afe8704d5b5f5558467a8bd90c946ea7c546e289",
    "kdf9": "rk354di8uCR1ZhWKUMUDqAozdXzY79rpFpBCYJgx7",
    "kdf8": "rk354dTvfAMWqXJt9vuFtdEyaNPg5A3U62xkWGs3B",
    "creation date": "04-02-2014",
    "clear": "RK6nEmXZj2nqgtCVWk3s7Suvz2XtWrdhDPpJqS",
    "fake_privkey8": "22630d1aeca9077f9eedc6b794c65ced3505321452479cc79181a3f2405347e3",
    "fake_privkey1": "3e2ca091e00b9f4de4c74e52a378989bcbcd54ee4ca3ffbce6c4e0dd5a8a0b0a",
    "kdf0": "rk354bWG4E9XxAdMuNCE3HexALH89MenMNyPbWWu9"
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

