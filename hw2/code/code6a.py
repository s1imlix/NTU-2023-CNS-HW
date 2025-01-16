from pwn import *
from cipher import *
from grabber import *
from code6b_lib import *
import random
import threading

wait_list = []

def sendline_wrapper():
    while len(wait_list) > 0:
        to_send = random.randint(0, len(wait_list) - 1)
        print('Sending: ' + wait_list[to_send].decode())
        conn.sendline(wait_list[to_send])
        wait_list.pop(to_send)

pub_key = [{}, {}, {}, {}] # server0, 1, 2, bob
n = 0
e = 0
d = 0 # mixer
conn = remote('cns.csie.org', 3001)
for i in range(4):
    key_pair = conn.recvline().decode().split(' ')[-2:]
    pub_key[i]['n'] = int(key_pair[0].strip('(,'))
    pub_key[i]['e'] = int(key_pair[1].strip(')\n'))

mixer_line = [i.decode().split(' ')[-2:] for i in conn.recvlines(3)[-2:]]
print(mixer_line)
n = int(mixer_line[0][0].strip('(,'))
e = int(mixer_line[0][1].strip(')\n'))
d = int(mixer_line[1][1].strip(')\n'))

pk = (n, e)
sk = (n, d)
conn.recvuntil('...\n') # till packet flow
thres = 10
while True:
    packet_hex = conn.recvline().decode()
    if 'CNS' in packet_hex:
        locate_flag(packet_hex)
        break
    packet_bytes = bytes.fromhex(packet_hex)
    # Try to decode message
    packet = Packet(packet_bytes)
    next_hop, next_pk = packet.decrypt_server(sk)
    next_str = '({}, {})'.format(next_hop, next_pk.data.hex())
    wait_list.append(next_str.encode())
    if len(wait_list) >= thres:
        sendline_wrapper()
    print('accumulated: ' + str(len(wait_list)))
