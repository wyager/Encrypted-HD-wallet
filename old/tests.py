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
'root key' : '000102030405060708090a0b0c0d0e0f',
'privkey' : 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35',
'creation date' : '04-02-2014',
'clear' : 'RK6nEaou4eFQC4SfrHtdh9jpnEme4K9dt2jBmG',
'password' : 'Satoshi',
'fake_password' : 'Alpaca',
'salt_entropy' : 'abcd',
'kdf0' : 'rk354bQrbuzi9tVCt48rv9CCrc1Mi7sk9m3Yykpt3',
'fake_privkey0' : 'cf345038e7b0068d50e796756a3df60314f6edb7bc47c9ee7b4d73678668cdcb',
'kdf1' : 'rk354bf4mvtwNXcLdcfppZECW4AoUBvTB8S23agNs',
'fake_privkey1' : '632c122124ba9905be5e02078d36ba63b7588edd2c68f1b385b9d6c2ca3e0817',
'kdf8' : 'rk354dNXRL2jSEL5Neh6ndDsxNgvRoP3Tt4oMqLTV',
'fake_privkey8' : 'a44ca5f6b4f38385e4a5cc751ace5d2117e3305aee52827286cbc981f00e80da',
'kdf9' : 'rk354dcjNKEyDFwVgYrdCQnkZYpUWzhyjMY16enLT',
'fake_privkey9' : '29e35fd44226c74117022b7e3079687bc2fa6391998753bc978509a8d9c5c323',
},
{
'root key' : '7f0ad7d595be13e6fe4cf1fa0fbb6ae9c26c5d9b09920709414982b6363d5844',
'privkey' : '08965cb883e1c8783d72b65a0b7104d64baa9412eb655a6f05c5aaa6103781be',
'creation date' : '04-02-2014',
'clear' : 'RK22qqMb3CozsQfTTbSVsLEgXcjekut99SuSHn6urU4vWxjiQneHWVYabWgv',
'password' : 'Nakamoto',
'fake_password' : 'hunter2',
'salt_entropy' : 'defg',
'kdf0' : 'rk2cMHcqyHdHNudopX8ZXwbrXgXK182FXpQJgiNdJbDGZXUpdWjfayTqi9tryTbS',
'fake_privkey0' : '7645740391ba1c5ef56286a1f43e8f95ac0b66de3bffb5ad3922ec140b7ad28f',
'kdf1' : 'rk2cMJD2R82kefxdoLEmXM3B8ox336pr2mbUNasLvEGKpZHzUMToWQyWmn6Y7szk',
'fake_privkey1' : 'ffd47e0d8fa64a9a696b4c3b7128fe416f1363aee1ddf6acfd2dd433c2e6bee6',
'kdf8' : 'rk2cMNLHXGrjxDyBtQvM1Ef5AxiGgtHympDceeMoCqj9mhqteoeFtPRpc1PXXMfd',
'fake_privkey8' : '96b831152e40d5461470729b88429c340de9c117c0d2af7564f91eb7e5f18443',
'kdf9' : 'rk2cMNvTy3VED3dCysRmZ6JswXAN2eYtA5oWegufDYNr7YQx2QHLbp3iie49u9Wf',
'fake_privkey9' : '391edef21757317e5bf1df133c0000ae86f982ad3b340ab5876a33fb057930a8',
},
{
'root key' : 'fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542',
'privkey' : '4b03d6fc340455b363f51020ad3ecca4f0850280cf436c70c727923f6db46c3e',
'creation date' : '04-02-2014',
'clear' : 'RK2BvY13FUD6bX25tA7XDyfAn7zbXSL8pR6TRE3EHZZ8qBm9qEyZRih8x1XhhcZwjcTfpe1Qjydn4KUdia8Wf1NshUusP1D38i88MLU9',
'password' : 'Vires In Numeris',
'fake_password' : 'Quis Custodiet Ipsos Custodes?',
'salt_entropy' : 'hijk',
'kdf0' : 'rk5ySVNYwdRMDLnyxs1pXCdN3wrcBdPziWUudFidmwSfcJaZKPH8U24WSegPhidQiD7tXejMNQfxrARh9JG8jLFtMY39fo9unpB4PsPSKymqy',
'fake_privkey0' : '0625f1c1e50cb7c3f302ff37d5eaa0fe20f45b10eb13634f4403b71dd3e49526',
'kdf1' : 'rk5ySW9NGHgAxs48UvF5oWvb6PHsZte43p1vjKmYuybLyGNrSMVHAkypTfb9qLFNTFixfCrxqnT3a8Vc5UoTcBzRxjLQAwYMoB7YcmzCWdVtD',
'fake_privkey1' : '4a525d10640a9ccd26bbcc1af8a4803803e97628b7e7b6f0db5376c94021c83b',
'kdf8' : 'rk5ySbZ5WuX3ba2Pudt1HE6iDQf7cSMg4zTsWbMKdFhucAwJEjNwH48oqCC52mbh3jxTQEGXN294AzxYsDbJowkiHSocGqWh7SFy24sE9KHGn',
'fake_privkey8' : '83d025017755701dbfcf5b50d07a95a99d517c15f40f0bec5529ae1cc3e39ba0',
'kdf9' : 'rk5yScKtqZmWe5FAB54x7WvvuxDSnNg81J3CADPdh4GJ4t2QaHckv8iuWF2spbC6uDC7DSM3GkYSQvNtz88su2h89vj9yUpmECmeELH2TkzM5',
'fake_privkey9' : 'c16e82babbf14512c9acde344a817693d2f401d2c73c7aeacdd21c455a9d5dd8',
},
{
'root key' : '6ca4a27ac660c683340f59353b1375a9',
'privkey' : 'f544dd076ffe8fb68aa81ca9a33059946e9a91f8d95258ae1b7a1db6215ce51a',
'creation date' : '04-02-2014',
'clear' : 'RK6nEmXZj2nqgtCVWk3s7Suvz2XtWrdhDPpJqS',
'password' : "\xe8\x81\xa1\xe4\xb8\xad\xe6\x9c\xac",
'fake_password' : 'Bitcoin',
'salt_entropy' : 'lmno',
'kdf0' : 'rk354bWG9c8dupPhhYsKgFEcZ8uqxV7JKbvbsmnzh',
'fake_privkey0' : 'b5af32696fe4bd75015d55f52a5bec16af4de74c256458ba8fdba7702509b7ca',
'kdf1' : 'rk354bkUKo7gu3vhdadunrCUSSjJuQrQwyRXoydTE',
'fake_privkey1' : 'de80aba55dee465b979a71a90d43c9a1f594eaaa30086944b8280603783ff4b8',
'kdf8' : 'rk354dTvdLGCSSPHP8tjFeLXMhwybvE47szr2jUPH',
'fake_privkey8' : '54b9fbe968a76327b452d0f7af1c74dfff34cddc4884ec6c65d1d1f66b3df79d',
'kdf9' : 'rk354di8idN7qLmnbYSsFgjPbeHQ4b9CxSSviqXiH',
'fake_privkey9' : '247f6877db617c7a28a45c44a97041d055f0c664f109e2b6c1f3d9702dcaaeaa',
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
            print "ERROR: On vector %i, the cleartext wallet is different." % (i+1)
            print v['clear']
            print b58(bip38v2.make_wallet(root, weeks, passphrase = None))
        else:
            print "clear OK"

        recovered_root = bip38v2.decrypt_wallet(b58d(v['clear']))[3]
        if recovered_root == root:
            print "Decrypted wallet OK (clear)"
        else:
            print "ERROR: Error decrypting wallet (clear)"

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
                print "ERROR: Error decrypting wallet (kdf{})".format(kdf)
            recovered_fake_root = bip38v2.decrypt_wallet(b58d(v['kdf'+str(kdf)]), passphrase=fake_password)[3]
            recovered_fake_master = crypto.generate_master_secret(recovered_fake_root)
            if recovered_fake_master == v['fake_privkey'+str(kdf)].decode('hex'):
                print "Decrypted wallet w/fake password OK (kdf{})".format(kdf)
            else:
                print "ERROR: Error decrypting wallet with fake password (kdf{})".format(kdf)
            generated_wallet = b58(bip38v2.make_wallet(root, weeks, passphrase=password, fake_passphrase=fake_password, salt_entropy=v['salt_entropy'], kdf_type=kdf))
            if generated_wallet == v['kdf'+str(kdf)]:
                print "Generated the same encrypted wallet with kdf " + str(kdf)
            else:
                print "ERROR: Error generating the same encrypted wallet with kdf " + str(kdf)

# Print out the test vectors in nice, copy-pastable JSON
def pretty_print_vectors(vectors):
    for vector in vectors:
            print '{'
            for key in ['root key', 'privkey', 'creation date', 'clear', 'password', 'fake_password', 'salt_entropy', \
                 'kdf0', 'fake_privkey0', 'kdf1', 'fake_privkey1', 'kdf8', 'fake_privkey8', 'kdf9', 'fake_privkey9']:
                print """\'{}\' : \'{}\',""".format(key, vector[key])
            print '},'

# Print out the vectors in forum markup
def gen_markup(vectors):
    keys = [
    ('root key', 'Root Key'),
    ('privkey', 'Private Key'),
    ('creation date', 'Creation Date'),
    ('clear', 'Cleartext Wallet'),
    ('password', 'Password'),
    ('fake_password', 'Fake Password'),
    ('salt_entropy','Salt Entropy'),
    ('kdf0', 'Encrypted with KDF 0'),
    ('fake_privkey0', 'Fake Private Key 0'),
    ('kdf1', 'Encrypted with KDF 1'),
    ('fake_privkey1', 'Fake Private Key 1'),
    ('kdf8', 'Encrypted with KDF 8'),
    ('fake_privkey8', 'Fake Private Key 8'),
    ('kdf9', 'Encrypted with KDF 9'),
    ('fake_privkey9','Fake Private Key 9'),
    ]
    result = ""
    for vector in vectors:
        result += "[table]\n"
        for (key, human_key) in keys:
            result += "[tr][td]{}[/td][td]{}[/td][/tr]\n".format(human_key, vector[key])
        result += "[/table]\n\n"
    return result