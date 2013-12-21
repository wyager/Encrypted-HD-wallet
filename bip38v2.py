# Will Yager's implementation of the in-development encrypted hierarchical deterministic wallet spec
# You may need to install slowaes, scrypt, and base58. All are available through `pip install [whatever]`
import aes 
import hashlib
import hmac
import scrypt
from datetime import date

# Encrypt with AES ECB. Key must be 32 bytes (256 bits). Data can be 16, 32, or 64 bytes.
def aes_encrypt(data, key):
	if len(data) != 16 and len(data) != 32 and len(data) != 64:
		raise Exception("Data is incorrect length: " + str(len(data)))
	if len(key) != 32:
		raise Exception("Key is incorrect length: " + str(len(key)))
	key = map(ord, key) # Convert key and data to a list of ints
	data = map(ord, data)
	e = aes.AES()
	result = ''
	for i in range(len(data)/16):
		block = e.encrypt(data[16*i : 16*i + 16], key, 32)
		result = result + ''.join(map(chr, block))
	return result

# Decrypt with AES ECB. Key must be 32 bytes (256 bits). Data can be 16, 32, or 64 bytes.
def aes_decrypt(data, key):
	if len(data) != 16 and len(data) != 32 and len(data) != 64:
		raise Exception("Data is incorrect length: " + str(len(data)))
	if len(key) != 32:
		raise Exception("Key is incorrect length: " + str(len(key)))
	key = map(ord, key) # Convert key and data to a list of ints
	data = map(ord, data)
	e = aes.AES()
	result = ''
	for i in range(len(data)/16):
		block = e.decrypt(data[16*i : 16*i + 16], key, 32)
		result = result + ''.join(map(chr, block))
	return result


# Hash with SHA 256
sha_hash = lambda data : hashlib.sha256(data).digest()

# Hash with RIPEMD-160
ripe_hash = lambda data : hashlib.new('ripemd160', data).digest()

# Hash with HMAC-SHA512
hmac_hash = lambda key, data : hmac.new(key, data, hashlib.sha512).digest()


def generate_master_secret(root_key):
	"""
	Compute generate_master_secret(root_key).
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

def generate_hash_function(hash_id):
	"""
	generate_hash_function(hash_id)
	takes an integer, hash_id, as defined in the spec and
	returns the related hash function.
	"""
	if hash_id == 0:
		return lambda data, salt, output_len : scrypt.hash(data, salt, pow(2,14), 8, 8, output_len)
	elif hash_id == 1:
		return lambda data, salt, output_len : scrypt.hash(data, salt, pow(2,16), 16, 16, output_len)
	elif hash_id == 2:
		return lambda data, salt, output_len : scrypt.hash(data, salt, pow(2, 18), 16, 16, output_len)
	else:
		raise Exception("Unknown hash ID")


def encrypt_root_key(prefix, date, root_key, hash_function, passphrase):
	"""
	Compute encrypt_root_key(prefix, date, root_key, hash_function, passphrase).
	root_key is a BIP 0032 root key. It should be a 16/32/64-byte string.
	date should be an int, in the form of floor(weeks since jan 1 2013)
	prefix should be a 3-byte string
	hash_function should be a function that takes a key, a salt, and a length L and outputs an L byte string.
	passphrase should be a string
	The returned value is a string, being "prefix + date + checksum + encrypted_key", in the compressed format specified in the BIP.
	This implementation differs a bit from the current draft spec. I'm using the hash of the
	private key instead of the hash of the master Bitcoin public address, in order to
	prevent someone from trivially determining the master Bitcoin public address, had it ever
	appeared in the blockchain.
	"""
	if len(prefix) != 3:
		raise Exception("Invalid prefix length: " + str(len(prefix)))
	if type(date) != type(1):
		raise Exception("Date needs to be an int")
	if len(root_key) != 16 and len(root_key) != 32 and len(root_key) != 64:
		raise Exception("root key needs to be 16/32/64 bytes, but is " + str(len(root_key)))
	if type(root_key) != type(""):
		raise Exception("root key needs to be a string")
	master_secret = generate_master_secret(root_key) # Calculate the master Bitcoin private key
	checksum = sha_hash(sha_hash(master_secret))[0:4] # Used to verify that the user entered their password correctly upon decryption
	date = ("%04x" % date).decode('hex') # Convert to a 2-byte value
	salt = prefix + date + checksum
	H = hash_function(passphrase, salt, len(root_key) + 32)
	whitened_root_key = ''
	for i in range(len(root_key)):
		whitened_char = ord(root_key[i]) ^ ord(H[i])
		whitened_root_key += chr(whitened_char)
	encryption_key = H[-32:] # Use the last 32 bytes of H as a key
	encrypted_root_key = aes_encrypt(whitened_root_key, encryption_key)
	# Size:[3]      [2]    [4]        [16/32/64]
	return prefix + date + checksum + encrypted_root_key

def decrypt_root_key(encrypted_root_key, passphrase):
	"""
	decrypt_root_key(encrypted_root_key, passphrase)
	Takes a byte string containing the encrypted root key and associated data (prefix, etc.)
	and returns a tuple of (prefix, date, checksum, root key).
	"""
	prefix = encrypted_root_key[0:3]
	wallet_type = int(prefix[0:2].encode('hex'), 16)
	# This dictionary maps prefixes to (starting bottom byte values, key length, # wallet factors)
	prefix_values = {0x0b2d: (0x7b, 16, 1), 0x1482: (0x17, 32, 1), 0x0130: (0xb7, 64, 1), 0x14d6: (0x0d, 16, 2), 0x263a: (0xa2, 32, 2), 0x0238: (0x04, 32, 2)}
	if wallet_type not in prefix_values:
		raise Exception("Unknown prefix")
	kdf_type = int(prefix[2].encode('hex'), 16) - prefix_values[wallet_type][0]
	date = encrypted_root_key[3:5]
	checksum = encrypted_root_key[5:9]
	encrypted_key = encrypted_root_key[9:]
	if len(encrypted_key) != prefix_values[wallet_type][1]:
		raise Exception("Length of key does not match length specified in prefix: " + len(encrypted_key))
	salt = encrypted_root_key[0:9]
	hash_function = generate_hash_function(kdf_type)
	H = hash_function(passphrase, salt, len(encrypted_key) + 32)
	encryption_key = H[-32:] # Use the last 32 bytes of H as a key
	decrypted_key = aes_decrypt(encrypted_key, encryption_key)
	unwhitened_root_key = ''
	for i in range(len(decrypted_key)):
		unwhitened_char = ord(decrypted_key[i]) ^ ord(H[i])
		unwhitened_root_key += chr(unwhitened_char)
	master_secret = generate_master_secret(unwhitened_root_key) # Calculate the master Bitcoin private key
	calculated_checksum = sha_hash(sha_hash(master_secret))[0:4] # Used to verify that the user entered their password correctly upon decryption
	if checksum != calculated_checksum:
		raise Exception("Password incorrect. Checksum mismatch. Expected " + checksum.encode('hex') + " but calculated " + calculated_checksum.encode('hex'))
	return prefix, date, checksum, unwhitened_root_key

# A test function to generate a simple encrypted wallet
def make_simple_wallet(root_key, passphrase):
	if len(root_key) != 32:
		raise Exception("Root key must be 32 bytes")
	prefix = 0x148217 # 32 byte 1-factor key
	prefix += 0x00 # Add the hash function ID to the prefix
	prefix = hex(prefix)[2:].decode('hex')
	weeks = (date.today() - date(2013, 1, 1)).days/7 - 1 # The -1 is to be safe
	hash_function = generate_hash_function(0x00)
	return encrypt_root_key(prefix, weeks, root_key, hash_function, passphrase)

import os
import sys
import base58
if __name__ == '__main__':
	if '--randomkey' in sys.argv:
		random_bytes = os.urandom(32)
		print "Root key: " + random_bytes.encode('hex')
	elif '--encrypt' in sys.argv:
		root_key = raw_input("Enter the root key in hex: ").decode('hex')
		password = raw_input("Enter the password: ")
		data = make_simple_wallet(root_key, password)
		text = base58.b58encode_check(data)
		print text
	elif '--decrypt' in sys.argv:
		base58_data = raw_input("Enter the encrypted wallet: ")
		recovered_data = base58.b58decode_check(base58_data)
		password = raw_input("Enter the password: ")
		print "Root key:" + decrypt_root_key(recovered_data, password)[3].encode('hex')
	else:
		print """
		Use --randomkey to make a new root key. Not guaranteed to make a valid key.
		Use --encrypt to encrypt the key.
		Use --decrypt to decrypt the wallet.
		"""