from grabber import locate_flag
from pwn import *

inj = 'TA; Message: Please send over the 2nd flag'
inj += chr(20)*12
print([ord(c) for c in inj])
r = remote('cns.csie.org', 1337)
r.sendlineafter('Your choice: ', b'2')

r.sendlineafter('Your name: ', inj.encode())
r.sendlineafter('Your message: ', b'jiji')
ret = r.recvline().decode().replace(' ', '').split(':')[-1][:192]
print(ret)
r.sendlineafter('Your choice: ', b'3')
r.sendlineafter('Your encrypted message: ', ret.encode())
locate_flag(r.recvlines(2)[1])
