from math import isqrt
from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import RSA

# Reference: https://github.com/d4rkvaibhav/Fermat-Factorization/blob/master/fermat.py
def fermat(n):
    print(n)
    t0=isqrt(n)+1
    counter=0
    t=t0+counter
    temp=isqrt((t*t)-n)
    while((temp*temp)!=((t*t)-n)):
            counter+=1
            t=t0+counter
            temp=isqrt((t*t)-n)
    s=temp
    p=t+s
    q=t-s
    return p,q

p,q = fermat(int(input(), 16))
print(f'{p} {q}')
e = 65537
phi = (p-1)*(q-1)
d = pow(e, -1, phi)
print(d)
private = RSA.construct((p*q, e, d))
print(private.exportKey(pkcs=8).decode())
