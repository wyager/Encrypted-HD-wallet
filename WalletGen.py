import crypto
import ssss
import bip38v2
import formatting
from os import urandom
from datetime import date

def generate_wallet_params():
    # Except for Shamir's Secret Sharing, this is the only part of the specification that requries randomness.
    key = urandom(32)
    salt = urandom(2)
    wallet_id = urandom(2)
    weeks = (date.today() - date(2013, 1, 1)).days/7
    return key, salt, wallet_id, weeks

def make_encrypted_wallet(passphrase, fake_passphrase, kdf_type, key, salt, weeks):
    assert(len(key) == 32)
    assert(len(salt) == 2)
    assert(weeks >= 0 and weeks < 65535)
    assert(kdf_type in crypto.kdfs)
    encrypted_wallet = bip38v2.make_wallet(key, weeks, passphrase, fake_passphrase, kdf_type, salt)
    return encrypted_wallet
    
def split_wallet(encrypted_wallet, wallet_id, m, n):
    assert(m <= n)
    assert(n < 16) 
    assert(len(wallet_id) == 2)
    shares = ssss.share(encrypted_wallet, m, n)
    # Share format: [4 bits share ID][4 bits # shares needed][2 bytes wallet ID][40 byte share]
    shares = [chr(((x-1) << 4) + m) + wallet_id + share for (x,share) in shares]
    return shares

def example_create_wallet():
    # All user-provided values
    passphrase = "hunter2"
    fake_passphrase = "Plausible_Deniability123"
    kdf_type = 0 # Low difficulty Scrypt
    m = 4 # Number of shares needed to reconstruct wallet
    n = 5 # Number of shares to create
    # Generate all random values
    key, salt, wallet_id, weeks = generate_wallet_params()
    # Now we'll encrypt and format the wallet
    encrypted_wallet = make_encrypted_wallet(passphrase, fake_passphrase, kdf_type, key, salt, weeks)
    # Now we'll split the wallet into some shares
    wallet_shares = split_wallet(encrypted_wallet, wallet_id, m, n)
    # Now we'll format those shares
    base58_shares = formatting.base58_format_shares(wallet_shares)
    return base58_shares

def reconstruct_wallet(shares, passphrase):
    wallet_ids = [share[1:3] for share in shares]
    if not all([wallet_id == wallet_ids[0] for wallet_id in wallet_ids]):
        raise Exception("Error: Trying to combine shares of different wallets")
    shares_needed = ord(shares[0][0]) & 0xF
    if not len(shares) >= shares_needed:
        raise Exception("Error: Not enough shares to reconstruct wallet")
    x_coords = [(ord(share[0]) >> 4) + 1 for share in shares]
    y_coords = [share[3:43] for share in shares]
    shares = zip(x_coords, y_coords)
    encrypted_wallet = ssss.reconstruct(shares, shares_needed)
    return bip38v2.decrypt_wallet(encrypted_wallet, passphrase)

if __name__ == '__main__':
    print example_create_wallet()