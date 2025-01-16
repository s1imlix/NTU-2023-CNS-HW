from code6b_lib import *
from pwn import *
from grabber import *

key_list = []
conn = remote('cns.csie.org', 3002)
for i in range(11):
    line = conn.readline().decode()
    server_key_str = line.split(' ')[-2:]
    n = int(server_key_str[0].strip('(,'))
    e = int(server_key_str[1].strip(')\n'))
    key_list.append((n, e))

# print('Key extracted:', key_list)

msg = b'Give me flag, now!'

conn.recvuntil('[')
server_list = [int(i.strip(' ]')) for i in conn.recvuntil(']').decode().split(',')]
print(server_list)
send_to = server_list[-1]

base_packet = Packet.create(msg, send_to, key_list[send_to])
for i in range(2, len(server_list)+1):
    print('Adding next hop:', server_list[-i])
    base_packet.add_next_hop(server_list[-i+1], key_list[server_list[-i]])

conn.sendline(base_packet.data.hex())
locate_flag(conn.recvall().decode())
