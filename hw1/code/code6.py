from Crypto.Util.number import long_to_bytes
from sympy.ntheory.modular import crt
import pwn
from art import text2art
from grabber import *
import itertools
import base64
from tqdm import trange
import math
import sys
from gmpy2 import iroot
import owiener

def one():
    conn, dic = p6_grabber('affine')
    print(f'n: {dic["n"]} Paste the number to https://www.dcode.fr/prime-factors-decomposition and put back n=pq')
    p = int(input('p: '))
    q = int(input('q: '))
    c = int(dic['c'])
    e = int(dic['e'])

    N=p*q
    r = (p-1) * (q-1)
    d = pow(e, -1, r)
    n = pow(c, d, N)
    locate_flag(long_to_bytes(n).decode())

def xgcd(a, b, s1 = 1, s2 = 0, t1 = 0, t2 = 1):
    # Extended Euclidean Algorithm
    if (b == 0):
        return abs(a), 1, 0
   
    q = math.floor(a/b)
    r = a - q * b
    s3 = s1 - q * s2
    t3 = t1 - q * t2
   
    return (abs(b), s2, t2) if (r == 0) else xgcd(b, r, s2, s3, t2, t3)

def two():
    conn, dic = p6_grabber('bob')
    n = int(dic['n'])
    b, s, t = xgcd(int(dic['e1']), int(dic['e2']))
    (c1, c2) = (int(dic['c1']), int(dic['c2']))
    i = pow(c1, -1, n)
    res = 1
    for k in range(-s):
        res = res * i % n
    for k in range(t):
        res = res * c2 % n
    locate_flag(long_to_bytes(res).decode())

def three():
    e=7
    n = []
    c = []
    sys.set_int_max_str_digits(10000)

    for i in range(e):
        r, dic = p6_grabber('eve')
        n.append(int(dic['n']))
        c.append(int(dic['c']))
        r.close()

    mp, _ = crt(n, c)
    print("m^e solution = ", mp)
    m = iroot(mp, 7)
    locate_flag(long_to_bytes(m[0]).decode())

def four():
    conn, dic = p6_grabber('admin')
    n = int(dic['n'])
    e = int(dic['e'])
    c = int(dic['c'])
    d = owiener.attack(e, n)
    m = pow(c, d, n)
    locate_flag(long_to_bytes(m).decode())

if __name__ == "__main__":
    Art = text2art('P6 Solver')
    print(Art)

    while True:
        res = input('Select the challenge (1-4) or quit (q): ')
        if res == 'q':
            break
        elif res == '1':
            print_title('6-1')
            one()
        elif res == '2':
            print_title('6-2')
            two()
        elif res == '3':
            print_title('6-3')
            three()
        elif res == '4':
            print_title('6-4')
            four()
        else:
            print('Invalid input')
            continue
