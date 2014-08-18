import hashlib
import hmac

def generate_master_secret(root_key):
    """
    generate_master_secret(root_key).
    root_key is a BIP 0032 root key. It should be a string.
    The returned value is a valid Bitcoin private key, in byte string format.
    """
    I = hmac_hash("Bitcoin seed", root_key) # See BIP 0032. This is used to generate the master secret and master chain.
    master_secret_string = I[0:32] # The value of the master secret, as a string
    master_secret = int(master_secret_string.encode('hex'), 16) # The integer value of the master secret
    curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    if master_secret == 0 or master_secret >= curve_order:
        raise Exception("Specified root key generates invalid secret")
    return master_secret_string