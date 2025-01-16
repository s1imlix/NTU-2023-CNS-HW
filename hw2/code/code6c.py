from pwn import *
from code6b_lib import *
from grabber import locate_flag
import subprocess

def sage_factorize(n):
    proc = subprocess.Popen(['sage'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)    
    proc.stdin.write(f'print(list(factor({n})))\n'.encode())
    proc.stdin.flush()
    out_list = proc.communicate()[0].decode().split('sage: ')
    factors = out_list[-2].split('(')[1:]
    p = int(factors[0].split(',')[0])
    q = int(factors[1].split(',')[0])
    return p, q

def find_private(pk):
    n, e = pk
    print('public key:', pk)
    p, q = sage_factorize(n)
    print('factorized: p =', p, 'q =', q)
    phi = (p - 1) * (q - 1)
    d = pow(pk[1], -1, phi)
    print('d =', d)
    print('appending:', (n, d))
    return (n, d)

pub_key_list = []
priv_key_list = []
conn = remote('cns.csie.org', 3003)
for i in range(11):
    line = conn.recvline().decode()
    server_key_str = line.split(' ')[-2:]
    n = int(server_key_str[0].strip('(,'))
    e = int(server_key_str[1].strip(')\n'))
    pub_key_list.append((n, e))
    priv_key_list.append(find_private((n, e)))


print(pub_key_list)
print(priv_key_list)

next_hop = int(conn.recvlines(2)[1].decode().split('mix')[1].strip(':'))
packet = Packet(bytes.fromhex(conn.recvline().decode().strip()))

while True:
    try:
        next_hop, next_packet = packet.decrypt_server(priv_key_list[next_hop])
        packet = next_packet
        print('next_hop:', next_hop)
    except Exception as e:   
        print(e)
        locate_flag(packet.decrypt_client(priv_key_list[next_hop]))
        break
