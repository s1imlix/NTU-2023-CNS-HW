import random
from Crypto.Util.number import getPrime
from Crypto.Util.number import inverse


def xor(a, b):
    return bytes([ai ^ bi for ai, bi in zip(a, b)])

def randbytes(n):
    return bytes([random.randrange(256) for _ in range(n)])

class StreamCipher:
    @staticmethod
    def encrypt(k: int, m: bytes) -> bytes:
        random.seed(k)
        key = randbytes(len(m))
        return xor(key, m)

    @staticmethod
    def decrypt(k: int, c: bytes) -> bytes:
        random.seed(k)
        key = randbytes(len(c))
        return xor(key, c)


class PublicKeyCipher:
    @staticmethod
    def gen_key():
        p, q = getPrime(64), getPrime(64)
        n = p * q
        phi_n = (p - 1) * (q - 1)
        e = 65537
        d = inverse(e, phi_n)
        return (n, e), (n, d)

    @staticmethod
    def encrypt(pk, m: int) -> bytes:
        n, e = pk
        r = randbytes(16)
        r_i = int.from_bytes(r, 'big')
        return r + pow(r_i + m, e, n).to_bytes(16, 'big')

    @staticmethod
    def decrypt(sk, c: bytes) -> int:
        n, d = sk
        r, c = c[:16], c[16:]
        r_i = int.from_bytes(r, 'big')
        c_i = int.from_bytes(c, 'big')
        return (pow(c_i, d, n) - r_i + n) % n
