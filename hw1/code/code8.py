from pwn import *
from grabber import *
import subprocess
import hashlib
import random

def sha256(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    h = hashlib.sha256()
    h.update(s)
    return h.hexdigest()

def sha256byte(s) -> bytes:
    if isinstance(s, str):
        s = s.encode()
    h = hashlib.sha256()
    h.update(s)
    return h.digest()

def read_pdf_as_bytes(filename):
    filename = filename.strip('\n')
    with open(filename, 'rb') as file:
        pdf_bytes = file.read()
    return pdf_bytes

r = remote('cns.csie.org', 9010)
r.recvlines(2)
target = r.recvline().decode().split(' ')[-1]
target = target[:-2]

contain_key = 'CNS2024'

print(f'get target {target}')

# dic = {}
#if target in dic:
#    print(dic[target])
while True:
    ran_num = random.randint(0, 100000000000)
    hash_str = contain_key + str(ran_num)
    long_sha = sha256(hash_str)
    sha_val = long_sha[-6:]
    #dic[sha_val] = hash_str
    if sha_val == target:
        print(hash_str)
        break

r.sendline(hash_str)
r.sendlineafter('Your choice: ', b'1')
r.sendlineafter('Product name: ', read_pdf_as_bytes(input('First PDF filename: ')))
r.sendlineafter('Amount: ', b'10')
print(r.recvline())
r.sendlineafter('Your choice: ', b'1')
r.sendlineafter('Product name: ', read_pdf_as_bytes(input('Second PDF filename: ')))
r.sendlineafter('Amount: ', b'10')
print(r.recvline()) # did we succeed

r.sendlineafter('Your choice: ', b'2')
print(r.recvline())
r.sendlineafter('Your choice: ', b'2')
print(r.recvline())
r.sendlineafter('Your choice: ', b'2')
print(r.recvline())
r.sendlineafter('Your choice: ', b'3')
prGreen('Part 1 done')
locate_flag(r.recvlines(2)[1].decode())

# Part 2

print(r.recvlines(16))
key_line = r.recvline()
print(key_line)
key_line_trailing = key_line.decode().split(' ')[-1]
key = key_line_trailing[:-2]
print(key)
contain_key += key

print(f'contain_key: {contain_key}')

dic = {}

pair = []
while True:
    ran_num = random.randint(0, 100000000000)
    hash_str = contain_key + str(ran_num)
    sha_val = sha256byte(hash_str)[-4:]
    if sha_val in dic:
        print(f'check {hash_str} != {dic[sha_val]} and {sha256byte(hash_str)[-4:]} == {sha256byte(dic[sha_val])[-4:]}')
        pair.append(hash_str)
        pair.append(dic[sha_val])
        break
    else:
        dic[sha_val] = hash_str

r.sendlineafter('Your choice: ', b'1')
r.sendlineafter('Product name: ', pair[0].encode())
r.sendlineafter('Amount: ', b'10')
print(r.recvline())
r.sendlineafter('Your choice: ', b'1')
r.sendlineafter('Product name: ', pair[1].encode())
r.sendlineafter('Amount: ', b'10')
print(r.recvline()) # did we succeed

r.sendlineafter('Your choice: ', b'2')
print(r.recvline())
r.sendlineafter('Your choice: ', b'2')
print(r.recvline())
r.sendlineafter('Your choice: ', b'2')
print(r.recvline())
r.sendlineafter('Your choice: ', b'3')
prGreen('Part 2 done')
locate_flag(r.recvlines(2)[1].decode())

# Part 3

r.recvlines(4)
ID_hex_line = r.recvline().decode().split(' ')[3]
#print(ID_hex_line)
original_hash = ID_hex_line[:-1]
#print(ID_hex)
#original_hash = bytes.fromhex(ID_hex)
print(original_hash)

response = ''
for secret_len in range(40, 51):
	secret_len += 14 # key=
	print(f'trying len={secret_len}')
	result = subprocess.run(['./hash_extender', '--data', 'staff', '--secret', str(secret_len), '--append', 'admin', '--signature', original_hash, '--format', 'sha256'], stdout=subprocess.PIPE)
	print(result.stdout)
	ret_list = result.stdout.decode().split('\n')
	new_sig = ret_list[2].split(' ')[2].strip('\n')
	new_name = ret_list[3].split(' ')[2].strip('\n')
	print(f'sending new_sig={new_sig} and hex(new_name)={new_name}')
	r.sendlineafter('Your choice: ', b'1')
	r.sendlineafter('Show me your ID: ', new_sig.encode())
	r.sendlineafter('what\'s your Identity: ', bytes.fromhex(new_name))
	response = r.recvlines(2)[1].decode()
	if "CNS" in response:
		break
prGreen('Part 3 done')
locate_flag(response)
