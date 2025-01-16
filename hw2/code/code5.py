from pwn import *
from grabber import *
import subprocess
from Crypto.Util.number import long_to_bytes
from public import *

def LCG_next(current, p): 
    a = 0xc814b5bd7461e52483115b6fff1c020c96f1a90ce173a0877e7579acff457864eb5185531123b965f68286988b1e55d9c7b06915a8637f63294d661d44939aa7
    c = 0x6369d6d9eed8bda45c2764a559500a11a1e695a57554b5f5f904bea20377bd77df435169b8d2e0669fd1a3d4bc4776ef3849d4ae1e3b12e7c80ac23155435b8f
    return (a * current + c) % p

def p1():
    print_title('P1')
    alice = remote('cns.csie.org', 23461)
    bob = remote('cns.csie.org', 23462)
    bob.sendlineafter(b'> ', 'Alice')

    alice.recvuntil(b'a = ')
    a = alice.recvline().decode().strip()
    print('Getting a from Alice:', a)
    bob.sendline(a.encode())
    print('Sending a to Bob')
    bob.recvuntil(b'c = ')
    c = bob.recvline().decode().strip()
    print('Getting c from Bob:', c)
    alice.sendline(c.encode())
    print('Sending c to Alice')
    w = alice.recvline().decode().split(' ')[-1]
    print('Getting w from Alice:', w)
    bob.sendline(w.encode())
    print('Sending w to Bob')
    flag = bob.recvline().decode()
    locate_flag(flag)
    alice.close()
    bob.close()

def p2():
    print_title('P2')
    p = Carrol_Pub_Key['p']
    y = Carrol_Pub_Key['y']
    bob = remote('cns.csie.org', 23462)
    bob.sendlineafter(b'> ', b'Carrol')

    # A fake session to know c, a & w are just dummies
    bob.sendlineafter(b'a = ', b'1')
    bob.recvuntil(b'c = ')
    c = bob.recvline().decode().strip()
    cn = LCG_next(int(c), p)
    a = pow(pow(y,cn,p), -1, p)
    bob.sendlineafter(b'w = ', b'1')

    # Actual session
    bob.sendlineafter(b'> ', b'Carrol')
    bob.sendlineafter(b'a = ', str(a).encode())
    bob.sendlineafter(b'w = ', b'0')
    flag = bob.recvline().decode()
    locate_flag(flag)
    bob.close()

def p3():

    bob = remote('cns.csie.org', 23462)
    bob.sendlineafter(b'> ', b'Admin')
    bob.sendlineafter(b'a = ', str(admin_a).encode())
    bob.sendlineafter(b'w = ', str(admin_w).encode())
    flag = bob.recvline().decode()
    locate_flag(flag)
    _, c1, c2 = [i.decode().split(' ')[2] for i in bob.recvlines(3)]
    print('extracted c1 and c2', c1, c2)
    p4(int(c1), int(c2))
    bob.close()


def p4(c1, c2):

    p = Admin_Pub_Key['p']
    g = Admin_Pub_Key['g']
    y = Admin_Pub_Key['y']
    #p = 661212642378546192924748624541024689740821842358380172364713618643459510023722305413088030182631492908841097127749562097350991966861367802894693769192651196097109493538162562798405156876034846778509975723794909609967301695307547686524372786580268393227198048625785038842430426659507104287249949976852788451803
    #g = 11
    #y = 473937504506436414041535538509294931346348680042860443536520331642145579104015202856896766224656813436541285126692050996761600170005762950346371287435297297112624802649992670271803443843475097312381420702060015479099874054986979802284624053312622785460981925643488908311577507968487433583437557495056175274767
    p_str = "p = mod({}, {})\n".format(p-1, p).encode()
    g_str = "g = mod({}, {})\n".format(g, p).encode()
    y_str = "y = mod({}, {})\n".format(y, p).encode()
    # Start a subprocess running sage
    proc = subprocess.Popen(['sage'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    # declare p, g, y
    proc.stdin.write(p_str)
    proc.stdin.flush()
    proc.stdin.write(g_str)
    proc.stdin.flush()
    proc.stdin.write(y_str)
    proc.stdin.flush()
    
    # discrete_log
    proc.stdin.write(b'discrete_log(y, g, p)\n')
    proc.stdin.flush()
    # Read output
    out_list = proc.communicate()[0].decode().split('sage: ')
    print(out_list)
    x = int([i.strip('\n') for i in out_list if i.strip('\n').isdigit()][0])
    print('solved private key', x)
    locate_flag(long_to_bytes((c2 * pow(c1, -x, p)) % p))



if __name__ == '__main__':
    print_title('P5 solver')
    while True:    
        p = input('Select sub-problem (1-3) to solve, q to leave, 4 is solved with 3: ')
        if p == '1':
            p1()
        elif p == '2':
            p2()
        elif p == '3':
            p3()
        elif p == 'q':
            break
        else:
            print('Invalid input')

