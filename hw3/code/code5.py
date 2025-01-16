from pwn import *
from grabber import *
import base64
import random

def p1():
    r = remote('cns.csie.org', 44444)
    r.sendlineafter(b'(1/2/3/4)', b'1')
    m = int(r.recvline().decode().split(',')[0][-4:])
    r.recvlines(5)
    for round in range(32):
        print(f'Round {round+1}')
        i, j = [int(num.strip(')\n')) for num in r.recvline().decode().split('(')[-1].split(', ')]
        print(f'm = {m}, i = {i}, j = {j}')
        # Randomly choose bit vector of size m 
        u0 = [random.randint(0, 1) for _ in range(m)]
        jhat = [0] * (j) + [1] + [0] * (m-j-1)
        u1 = [u0[i] ^ jhat[i] for i in range(m)]
        # Send u0 and u1
        u0_line = ','.join(map(str, u0)).encode()
        u1_line = ','.join(map(str, u1)).encode()
        r.sendline(u0_line)
        r.sendline(u1_line)
        res = r.recvlines(6)
        #print(res)
        r0 = [int(bit) for bit in res[2].decode().split(', ')]
        r1 = [int(bit) for bit in res[5].decode().split(', ')]
        #print(f'r0 = {r0}, r1 = {r1}')
        Xj = [r0[i] ^ r1[i] for i in range(m)]
        #print(f'Xj = {Xj}')
        r.sendline(str(Xj[i]).encode())
        print(r.recvlines(1))  
    locate_flag(r.recvline().decode())
    r.close()

def p2():
    r = remote('cns.csie.org', 44444)
    r.sendlineafter(b'(1/2/3/4)', b'2')
    r.recvlines(2)
    for round in range(32):
        print(f'Round {round+1}')
        r.recvline()
        u0 = [int(bit) for bit in r.recvlines(2)[1].decode().split(', ')]
        u1 = [int(bit) for bit in r.recvlines(2)[1].decode().split(', ')]
        jhat = [u0[i] ^ u1[i] for i in range(len(u0))]
        print(jhat)
        r.sendline(str(jhat.index(1)))
    locate_flag(r.recvlines(2)[-1].decode())
    r.close()
    
def p3():
    pass

if __name__ == '__main__':
    print('P4 Solver')
    # Choose problem to solve 
    while True:
        choice = input('Enter problem number (1-3) or quit (q): ')
        if choice == '1':
            p1()
        elif choice == '2':
            p2()
        elif choice == '3':
            p3()
        elif choice == 'q':
            break
        else:
            print('Invalid choice. Try again.')

