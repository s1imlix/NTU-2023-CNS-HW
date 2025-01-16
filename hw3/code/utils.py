import signal
import hashlib
from binascii import unhexlify, hexlify
from Crypto.Cipher import Salsa20

# Timeout
def alarm(second):
    def handler(signum, frame):
        print('I think you are disconnect... Bye!')
        exit()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(second)

def H(*args):
    sha512 = hashlib.sha512()
    for arg in args:
        sha512.update(str(arg).encode())
    output = unhexlify(sha512.hexdigest())
    return int.from_bytes(output, 'big')

def cns_encrypt(key: bytes, msg: bytes) -> bytes:
    cipher = Salsa20.new(key=key)
    return hexlify(cipher.nonce + cipher.encrypt(msg)).decode()

def cns_decrypt(key: bytes, enc: bytes) -> bytes:
    msg = unhexlify(enc)
    nonce = msg[:8]
    c = msg[8:]
    cipher = Salsa20.new(key=key, nonce=nonce)
    return cipher.decrypt(c)