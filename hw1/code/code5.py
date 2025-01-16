import numpy as np
import pwn
from art import text2art
from grabber import *
import itertools
import base64
from tqdm import trange

def byteary_XOR(A, B):
    # assume len(A) <= len(B)
    ret = bytearray()
    la = len(A)
    lb = len(B)
    for i in range(lb):
        ret.append(A[i % la] ^ B[i])
    return ret
def isflagchar(c):
    return 32 <= ord(c) and ord(c) <= 126

def one():

    conn, byte_str, plain = p5_grabber('affine')

    hex_str = ' '.join(f'{byte:02x}' for byte in byte_str)
    clist = hex_str.split(' ')

    print(f'plain: {plain} and hex_str: {hex_str}')

    # init 
    n1 = int(clist[0], 16)
    n2 = int(clist[1], 16)
    a = 0
    b = 0

    # brute force
    for i in range(256):
        for j in range(256):
            if (n1*i+j)%256 == ord(plain[0]) and (n2*i+j)%256 == ord(plain[1]):
                a = i
                b = j
                break
    clist.pop(0)
    clist.pop(0)
    
    # Get passphrase
    for c in clist:
        ret = (a * int(c, 16) + b) % 256
        plain += chr(ret)
    print(plain)

    conn.sendlineafter('>', b'2')
    conn.sendlineafter('passphrase: ', plain.encode())
    locate_flag(conn.recvline())

def three():
    conn, byte_str, _ = p5_grabber('eve')
    encoded = byte_str.decode()
    unique = ''.join(set(encoded.replace(" ", "")))

    print(f'encoded: {encoded}')

    k1 = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    k2 = "ABCDEFGHJKLMNOPQRSTUVWXYZ"

    all_perm = {}
    pindex = 0

    for i in itertools.permutations(unique, 5):
        mapping = {}
        index = 0
        for char in i:
            mapping[char] = index
            index += 1
        wl1 = []
        wl2 = []
        for word in encoded.split(" "):
            dw1 = str()
            dw2 = str()
            for k in range(0, len(word), 2):
                # print(f'decoding {word[k]}{word[k+1]} = k1[{mapping[word[k]]}] * 5 + {mapping[word[k+1]]}')
                dw1 += k1[mapping[word[k]] * 5 + mapping[word[k+1]]]
                dw2 += k2[mapping[word[k]] * 5 + mapping[word[k+1]]]
            wl1.append(dw1)
            wl2.append(dw2)
            ret1 = ' '.join(wl1)
            ret2 = ' '.join(wl2)
        all_perm[pindex] = [ret1, ret2]
        print(f'perm_index: {pindex}, wl1: {ret1}, wl2: {ret2}')
        pindex += 1

    chosen_perm = int(input('Choose permutation index to send: '))
    perm_id = int(input('Choose ver1 or ver2 (1/2): '))
    print(f'Chosen permutation: {all_perm[chosen_perm][perm_id]}')
    conn.sendlineafter('>', b'4')
    conn.sendlineafter('passphrase: ', all_perm[chosen_perm][perm_id].encode())
    locate_flag(conn.recvline())

def four():
    r, byte_str, _ = p5_grabber('admin')
    passphrase = base64.b64decode(byte_str.decode())
    r.sendlineafter('> ', b'5')
    r.sendlineafter('passphrase: ', passphrase)

    otp_encrypted = bytearray(bytes.fromhex(r.recvlines(5)[4].decode().strip('\"')))

    given_plain = bytearray(b'CNS{')
    valid_plain = []

    prGreen('Brute forcing the one-time pad and all possible position: The only readable result is the flag.')
    for offset in trange(len(otp_encrypted) - 6):
        for fb in range(0, 256):
            for sb in range(0, 256):
                cur_plain = bytearray(given_plain)
                cur_key = byteary_XOR(cur_plain, otp_encrypted[offset:offset + 4])
                cur_key.extend([fb, sb])
                plain_byte = byteary_XOR(cur_key, otp_encrypted[offset:])
                try:
                    plain = plain_byte.decode('ascii')
                    if all([isflagchar(c) for c in plain]):
                        if '}' in plain:
                            print(plain)
                            valid_plain.append(plain)
                except UnicodeDecodeError:
                    continue
    print(valid_plain)

if __name__ == '__main__':
    Art = text2art("P5 Solver")
    print(Art)
    
    while True:
        res = input('Select the challenge (1-4) or quit (q): ')
        if res == 'q':
            break
        elif res == '1':
            print_title('5-1')
            one()
        elif res == '3':
            print_title('5-3')
            three()
        elif res == '4':
            print_title('5-4')
            four()
        else:
            print('No 5-2 solver, refer to pdf.')
