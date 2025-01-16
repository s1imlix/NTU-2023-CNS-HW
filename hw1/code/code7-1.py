from grabber import locate_flag
from pwn import *
from tqdm import trange
r = remote('cns.csie.org', 1337)


r.sendlineafter('Your choice: ', b'1')
recv = r.recvlines(2)[1].decode()
cipher = bytearray(bytes.fromhex(recv))
ascii_list = [int(c) for c in cipher]

ciphertext_byte = ascii_list
print(f'{len(ciphertext_byte)}')

byte_len = len(ciphertext_byte)
block_len = 16
plain_block_list = []
for block in range(byte_len // block_len-1, 0, -1):
    plain_block = []
    for start in range(15, -1, -1): # start of index to change ciphertext
        ciphertext_copy = ciphertext_byte.copy()
        print(f'block: {block} start: {start} len {len(ciphertext_copy)}')
        start_index = (block-1)*block_len + start
        padding_byte = 24-start
        # print(start_index)
        for i in range(0, 15-start):
            ciphertext_copy[start_index+i+1] = (ciphertext_byte[start_index+i+1] ^ ord(plain_block[i]) ^ padding_byte) % 256
        for guess in trange(256):
            ciphertext_copy[start_index] = guess
            hexary = [hex(c)[2:].zfill(2) for c in ciphertext_copy]
            hexlified_ciphertext = ''.join(hexary)
            r.sendlineafter('Your choice: ', b'3')
            r.sendlineafter('Your encrypted message: ', hexlified_ciphertext.encode())
            oracle_response = r.recvline()
            #print(oracle_response)
            if 'sent' in oracle_response.decode():
                print(f'Guess correct! guess = {guess}')
                answer = chr(guess ^ ciphertext_byte[start_index] ^ padding_byte)
                plain_block.insert(0, answer)
                print(plain_block)
                break
            # ciphertext_copy[start_index] = ciphertext_byte[start_index]
    ciphertext_byte = ciphertext_byte[:block*block_len]
    plain_block_list.append(''.join(plain_block))


plain_block_list.reverse()
plain_byte_except_first = ''.join(plain_block_list)
locate_flag(plain_byte_except_first)
