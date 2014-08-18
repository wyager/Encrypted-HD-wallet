import base58

def base58_format_shares(shares):
	shares = ["\xfb\xb3" + share for share in shares]
	return [base58.b58encode_check(share) for share in shares]