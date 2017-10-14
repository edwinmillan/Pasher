from random import SystemRandom
from hashlib import pbkdf2_hmac
from binascii import hexlify


def gen_salt(length):
    alphanumeric = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
    salt = ''.join(SystemRandom().choice(alphanumeric) for _ in range(length)).encode()
    return salt


def generate_pw_hash(password, salt=None, hash_name='sha256', salt_length=16, iterations=60000):
    salt = salt or gen_salt(salt_length)
    if isinstance(salt, str):
        salt = salt.encode()
    if isinstance(password, str):
        password = password.encode()
    if isinstance(iterations, str):
        iterations = int(iterations)

    raw_hash = pbkdf2_hmac(hash_name, password, salt, iterations)
    hex_hash = hexlify(raw_hash).decode()

    formatted_hash = f'pbkdf2${hash_name}${salt.decode()}${iterations}${hex_hash}'
    return formatted_hash



def validate_pw_hash(hashed_password, password):
    method, hash_name, salt, iterations, hex_hash = hashed_password.split('$')
    passhash_to_verify = generate_pw_hash(password, salt, hash_name, len(salt), iterations)
    return hashed_password == passhash_to_verify
