import crypto

def make_wallet(root_key, date, passphrase, fake_passphrase, kdf_type, salt):
	"""
	make_wallet(root_key, date, passphrase, fake_passphrase, kdf_type, salt)
	root_key :: 32 bytes (pseudo)-random data. 
	date :: Wallet creation date. Integer <= 65535. 
	   == ((creation day) - (2013-01-01)) / 7
	passphrase :: The passphrase to decrypt the wallet.
	fake_passphrase :: Alternate passphrase. Decrypts to a different wallet.
	kdf_type :: The numerical code for the desired KDF type.
	salt :: A 2-byte random value.
	Returns a wallet ciphertext, which can be decrypted with the passphrase.
	Format:
	[12 bit salt][4 bit KDF type][2 byte creation date][4 byte checksum][32 byte encrypted root_key]
	Salt goes first because SSSS works better with random most significant bits.
	"""
	assert(len(root_key) == 32)
	assert(date >= 0 and date <= 65535)
	assert(kdf_type in (0,1,2,8,9))
	assert(len(salt) == 2)
	big_endian_date = chr(date >> 8) + chr(date & 0xff)
	# Encode the KDF in the bottom 4 bits of the salt
	kdf_byte = chr( kdf_type + (ord(salt[1]) & 0xF0) )
	salt = salt[0] + kdf_byte
	# Use the provided salt value + the date as the salt
	new_salt = salt + big_endian_date # 4 byte salt

	kdf = crypto.kdfs[kdf_type]

	encrypted_root_key = crypto.encrypt_key(root_key, new_salt, passphrase, kdf)

	fake_root_key = crypto.decrypt_key(encrypted_root_key, new_salt, fake_passphrase, kdf)

	decryption_checksum = crypto.make_key_checksum(root_key, fake_root_key)

	return salt + big_endian_date + decryption_checksum + encrypted_root_key

def decrypt_wallet(wallet, passphrase):
	assert(len(wallet) == 2 + 2 + 4 + 32)
	salt = wallet[0:2]
	big_endian_date = wallet[2:4]
	new_salt = salt + big_endian_date
	decryption_checksum = wallet[4:8]
	encrypted_root_key = wallet[8:40]

	kdf_type = ord(wallet[1]) & 0x0F
	assert(kdf_type in (0,1,2,8,9))
	kdf = crypto.kdfs[kdf_type]

	root_key = crypto.decrypt_key(encrypted_root_key, new_salt, passphrase, kdf)

	if not crypto.check_key_checksum(root_key, decryption_checksum):
		raise Exception("Decryption checksum is bad. Is password incorrect?")

	date = (ord(big_endian_date[0]) << 8) + ord(big_endian_date[1])

	return root_key, date

