# Will Yager's implementation of PBKDF2-HMAC-SHA512
import hashlib
import hmac

string_xor = lambda a,b : ''.join([chr(ord(x)^ord(y)) for (x,y) in zip(a,b)])


# Hash with HMAC-SHA512
hmac_hash = lambda key, data : hmac.new(key, data, hashlib.sha512).digest()

pbkdf2_U = hmac_hash

def pbkdf2_F(password, salt, iterations, i):
    result = '\0'*64
    U = salt + chr((i>>24) & 0xFF) + chr((i>>16) & 0xFF) + chr((i>>8) & 0xFF) + chr((i>>0) & 0xFF)
    for i in xrange(iterations):
        U = pbkdf2_U(password, U)
        result = string_xor(result, U)
    return result

def pbkdf2(password, salt, iterations, output_len):
    output_blocks = output_len // 64
    if (output_len % 64) != 0:
        output_blocks += 1
    result = ''
    for i in range(1,output_blocks+1):
        result += pbkdf2_F(password, salt, iterations, i)
    return result[0:output_len]
