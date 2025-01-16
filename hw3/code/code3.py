from pwn import *
from grabber import *
import math
from sage.all import *

def hex2int(hexnum):
    bytes_data = bytes.fromhex(hexnum)
    hash_obj = hashlib.sha3_512(bytes_data)
    res = int.from_bytes(hash_obj.digest(), byteorder='big')
    # print(f'hex2int({hexnum}) = {res}')
    return res

def get_param(choice):
    print(f'Getting parameters for problem {choice}')
    r = remote('cns.csie.org', 9721)
    param = {}
    r.recvline()
    param['a'] = int(r.recvline().decode().split(' ')[-1].strip())
    param['b'] = int(r.recvline().decode().split(' ')[-1].strip())
    param['p'] = int(r.recvline().decode().split(' ')[-1].strip())
    param['g1'] = [int(i.strip('( ')) for i in r.recvline().decode().split('= ')[1].split(' : ')[:2]]
    param['g2'] = [i.strip('( ') for i in r.recvline().decode().split('= ')[1].split(' : ')[:2]] 
    param['cg1'] = [int(i.strip('( ')) for i in r.recvline().decode().split('= ')[1].split(' : ')[:2]]
    param['cg2'] = [i.strip('( ') for i in r.recvline().decode().split('= ')[1].split(' : ')[:2]]
    F1 = GF(param['p'], 'w') 
    F2 = GF((param['p'], 12), 'w')
    # F = GF(param['p'], names=('w',)); (w,) = F._first_ngens(1)
    E1 = EllipticCurve(F1, [param['a'], param['b']])
    E2 = EllipticCurve(F2, [param['a'], param['b']])
    r.sendlineafter(b'Your choice: ', str(choice).encode())
    if choice == 1 or choice == 2:
        c = int(r.recvline().decode().split(' ')[-1].strip())
        param['c'] = c
        hexnums = r.recvline().decode().split('=')[-1].strip(' []\n').split(', ')
        # print(f'hexnums: {hexnums}')
        param['A'] = math.prod([c - hex2int(hexnum.strip('\'')) for hexnum in hexnums])
        if choice == 2:
            return r, param, F1, E1, hexnums
    elif choice == 3 or choice == 4:
        #print(r.recvline().decode().split('Digest: ')[1].split(' : ')[:2])
        param['d'] = [int(i.strip('( ')) for i in r.recvline().decode().split('Digest: ')[1].split(' : ')[:2]]
    print(param, F2, E2)   
    return r, param, F1, E1, F2, E2

def p1():
    r, param, F, E, _, _ = get_param(1)
    g1 = E(param['g1'][0], param['g1'][1])
    for i in range(10):
        param['s'] = hex2int(r.recvuntil(b':').decode().split(' ')[-1].strip(':'))
        print(f'Round {i+1}: s = {param["s"]}')
        cms = param['c'] - param['s']
        proof = (param['A']//cms)*g1
        print(proof)
        r.sendline(str(proof).encode())
    locate_flag(r.recvlines(2)[1].decode().strip())
    r.close()

def p2():
    r, param, F, E, hexnums = get_param(2)
    g1 = E(param['g1'][0], param['g1'][1])
    for i in range(10):
        raw_u = r.recvuntil(b':').decode().split(' ')[-1].strip(':')
        print(f'raw_u: {raw_u}')
        param['u'] = hex2int(raw_u)
        b = math.prod([param['u'] - hex2int(hexnum.strip('\'')) for hexnum in hexnums])
        print(f'Round {i+1}: u = {param["u"]}')
        divd = param['c'] - param['u']
        qc = (param['A'] - b)//divd
        proof = qc*g1
        print(proof)
        r.sendline(str(proof).encode())
        r.sendline(str(b).encode())
        if i < 9:
            r.recvuntil(b'proof')
    locate_flag(r.recvlines(3)[2].decode().strip())   
    r.close()
    
def p3():
    r, param, _, E1, _, E2 = get_param(3)
    g1 = E2(param['g1'][0], param['g1'][1])
    g2 = E2(param['g2'][0], param['g2'][1])
    cg2 = E2(param['cg2'][0], param['cg2'][1])
    r.recvline()
    for i in range(10):
        param['x'] = hex2int(r.recvline().decode().split(' = ')[-1])
        print(f'Round {i+1}: x = {param["x"]}')
        pi_list = [int(i.strip('( ')) for i in r.recvline().decode().split('= ')[1].split(' : ')[:2]]
        pi = E2(pi_list[0], pi_list[1])
        dp = E2(param['d'][0], param['d'][1])
        g2cns = cg2 - param['x']*g2
        f1 = pi.weil_pairing(g2cns, E1.order())
        f2 = dp.weil_pairing(g2, E1.order())
        print(f'f1 = {f1}, f2 = {f2}')
        proof = f1 == f2
        if proof:
            r.sendline(b'y')
        else:
            r.sendline(b'n')
        if i < 9:
            r.recvlines(2)
    locate_flag(r.recvlines(3)[2].decode().strip())
    r.close()

def p4():
    r, param, _, E1, _, E2 = get_param(4)
    g1 = E2(param['g1'][0], param['g1'][1])
    g2 = E2(param['g2'][0], param['g2'][1])
    cg2 = E2(param['cg2'][0], param['cg2'][1])
    r.recvline()
    for i in range(10):
        param['x'] = hex2int(r.recvline().decode().split(' = ')[-1])
        print(f'Round {i+1}: x = {param["x"]}')
        pi_line = r.recvline().decode().split('= ')[1].split(' : ')
        pi_a = [int(i.strip('( ')) for i in pi_line[:2]]
        # print('pi_line:', pi_line, 'pi_a:', pi_a)
        #print(pi_line)
        b = int(pi_line[2].split(' ')[1].strip(')\n'))
        pi = E2(pi_a[0], pi_a[1])
        dp = E2(param['d'][0], param['d'][1])-b*g1
        g2cns = cg2 - param['x']*g2
        f1 = pi.weil_pairing(g2cns, E1.order()) 
        f2 = dp.weil_pairing(g2, E1.order())
        print(f'f1 = {f1}, f2 = {f2}')
        proof = f1 == f2
        if proof:
            r.sendline(b'y')
        else:
            r.sendline(b'n')
        if i < 9:
            if 'Incorrect' in r.recvline().decode():
                print('bruh')
            else:
                r.recvline()
    locate_flag(r.recvlines(3)[2].decode().strip())   
    r.close()

def embedding_degree(E, p):
    k = 1
    print('Factorization of order-1: ')
    factors = list(factor(E.order()-1))
    print(factors)
    return factors[0][0]

def p5():
    print('Embedding degree calculation')
    print('1. secp256k1')
    print('2. Curve25519')
    choice = input('Choose curve (1 or 2): ')
    if choice == '1':
        p = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f
        K = GF(p)
        a = K(0x0000000000000000000000000000000000000000000000000000000000000000)
        b = K(0x0000000000000000000000000000000000000000000000000000000000000007)
        E = EllipticCurve(K, (a, b))
        G = E(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8)
        E.set_order(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141 * 0x1)
    elif choice == '2':
        p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        K = GF(p)
        A = K(0x76d06)
        B = K(0x01)
        E = EllipticCurve(K, ((Integer(3) - A**Integer(2))/(Integer(3) * B**Integer(2)), (Integer(2) * A**Integer(3) - Integer(9) * A)/(Integer(27) * B**Integer(3))))
        G = E(*to_weierstrass(A, B, K(0x09), K(0x20ae19a1b8a086b4e01edd2c7748d14c923d4d7e6d7c61b229e9c5a27eced3d9)))
        E.set_order(0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed * 0x08)
    print(f'Embedding degree: {embedding_degree(E, p)}')

def to_weierstrass(A, B, x, y):
	return (x/B + A/(3*B), y/B)

def to_montgomery(A, B, u, v):
	return (B * (u - A/(3*B)), B*v)



if __name__ == '__main__':
    print('P3 Solver')
    # Choose problem to solve 
    while True:
        choice = input('Enter problem number (1-4) or embedding_degree calculator (5) or quit (q): ')
        if choice == '1':
            p1()
        elif choice == '2':
            p2()
        elif choice == '3':
            p3()
        elif choice == '4':
            p4()
        elif choice == '5':
            p5()
        elif choice == 'q':
            break
        else:
            print('Invalid choice. Try again.')
