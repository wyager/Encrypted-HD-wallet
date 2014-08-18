# Shamir's Secret Sharing Scheme for 320 bit values.

from os import urandom

# We need to share (2+2+4+32) bytes = 320 bits.
# We want the smallest prime > 2**320
prime = 2**320 + 27

def big_endian_decode(bytes):
	return sum([ord(byte) << (8*shift) for (shift, byte) in enumerate(bytes[::-1])])

def big_endian_encode(value):
	result = ""
	while value != 0:
		result += chr(value & 0xFF)
		value >>= 8
	return result[::-1]

def random_321_bit_int():
	random_bytes = urandom(41)
	random_int = big_endian_decode(random_bytes)
	return random_int & (2**321 - 1)

def random_int_less_than_prime():
	"""
	returns a random integer < 2**320 + 27
	"""
	random_int = random_321_bit_int()
	while random_int >= prime:
		random_int = random_321_bit_int()
	return random_int

def share(secret, m, n):
	"""
	share(secret, m, n)
	Secret is a 40 byte string.
	m is the number of shares needed to reconstruct secret.
	n is the number of shares to generate.
	"""
	secret = big_endian_decode(secret)
	assert(secret < prime)
	assert(m <= n)
	assert(n < prime) # Obviously, or this would never finish
	assert(m >= 1)
	random_coefficients = [random_int_less_than_prime() for i in range(m-1)]
	def f(x):
		# f(x) = secret + a1*x + a2*x^2 + ... + a(m-1)*x^(m-1)
		total = secret
		for exp, coeff in enumerate(random_coefficients):
			total += coeff * x**(exp+1)
		return total % prime
	return [(i+1, big_endian_encode(f(i+1))) for i in range(n)]

def reconstruct(shares, m):
	"""
	reconstruct(shares, m)
	Takes at least m unique shares, of an m-of-n shared secret,
	and returns the secret. Note: the secret will be front-padded
	with zeros if the binary representation takes less than 40 bytes.
	"""
	xs = [x for (x,y) in shares]
	ys = [big_endian_decode(y) for (x,y) in shares]
	# Lagrange basis polynomial
	def l(j,x):
		numerator = 1
		denominator = 1
		for i in range(0,m):
			if i != j:
				numerator *= (x - xs[i])
				denominator *= (xs[j] - xs[i])
		# Numerator times multiplicative inverse mod prime of denominator
		return numerator * pow(denominator, prime-2, prime)
	# Lagrange interpolation polynomial
	def L(x):
		total = 0
		for j in range(0,m):
			total += ys[j]*l(j,x)
		return total % prime
	secret = big_endian_encode(L(0))
	# Zero pad the secret
	return chr(0)*(40 - len(secret)) + secret 