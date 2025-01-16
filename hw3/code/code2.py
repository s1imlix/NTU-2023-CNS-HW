from pwn import *
from utils import cns_decrypt, cns_encrypt
from grabber import *
import base64

def p1():
    r = remote('cns.csie.org', 23471)
    r.sendlineafter('> ', b'1')
    # Register
    r.sendlineafter('username: ', b'cnsStudent')
    r.sendlineafter('password: ', b'testtest')
    user_info = {}
    user_info['username'] = 'cnsStudent'
    user_info['password'] = 'testtest'
    user_info['id'] = r.recvlines(4)[-1].decode().split(' ')[-1]
    user_info['symmetric_key'] = base64.b64decode(r.recvline().decode().split(' ')[-1].strip('\n').encode())
    print(user_info)
    print('Register success as cnsStudent')
    # Login
    r.sendlineafter('> ', b'2')
    r.sendlineafter('username: ', b'cnsStudent')
    r.sendlineafter('password: ', b'testtest')
    print('Login success as cnStudent')
    # Communicate
    r.sendlineafter('> ', b'3')
    r.sendlineafter('username: ', b'bob')
    r.sendlineafter('nonce: ', b'Hello')
    kdc_raw_msg = r.recvline().decode().split(' ')[-1].strip('\n')
    kdc_res = cns_decrypt(user_info['symmetric_key'], kdc_raw_msg.encode()).decode().split('||')
    print(kdc_res)
    K_AB = base64.b64decode(kdc_res[1].encode())
    forward_msg = kdc_res[-1]
    r.close()

    bob = remote('cns.csie.org', 23472)
    bob.sendlineafter('message: ', forward_msg.encode())
    bob_raw_msg = bob.recvline().decode().split(' ')[-1].strip('\n')
    N_B = int(cns_decrypt(K_AB, bob_raw_msg.encode()).decode())
    send_bob_msg = cns_encrypt(K_AB, str(N_B-1).encode())
    bob.sendlineafter('message: ', send_bob_msg.encode())
    last_msg = bob.recvline().decode().split(' ')[-1].strip('\n')
    locate_flag(cns_decrypt(K_AB, last_msg.encode()).decode())

def p2():
    r = remote('cns.csie.org', 23471)
    admin_passwd = b'm45t3rm1nd' # cracked from john
    r.sendlineafter('> ', b'2')
    r.sendlineafter('username: ', b'admin')
    r.sendlineafter('password: ', admin_passwd)
    locate_flag(r.recvline())

def p3():
    session_log = {'userA': 'alice', 'userB': 'bob', 'keyAB': 'LAuHQVA1OSWihulNOUVzydnHT2VA5i6y0G3SjIOj7bQ=', 'forward_message': 'd982ca4aa252c51164d0e103b68db88edbaeee47c33b1d50f4ee123ea5d3a770c490b0ff0f174b05a81042f179f3c2f42206d93d3663a3aae5fdaf'}
    bob = remote('cns.csie.org', 23472)
    bob.sendlineafter('message: ', session_log['forward_message'].encode())
    bob_raw_msg = bob.recvline().decode().split(' ')[-1].strip('\n')
    N_B = int(cns_decrypt(base64.b64decode(session_log['keyAB']), bob_raw_msg.encode()).decode())
    send_bob_msg = cns_encrypt(base64.b64decode(session_log['keyAB']), str(N_B-1).encode())
    bob.sendlineafter('message: ', send_bob_msg.encode())
    last_msg = bob.recvline().decode().split(' ')[-1].strip('\n')
    print(last_msg)
    locate_flag(cns_decrypt(base64.b64decode(session_log['keyAB']), last_msg.encode()).decode())

def p4():
    pass

if __name__ == '__main__':
    print('P2 Solver')
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

