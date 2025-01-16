import pwn

def prGreen(skk): print("\033[92m {}\033[00m" .format(skk))

def print_title(title, length=50):
    padding = (length - len(title)) // 2

    print("=" * length)
    print(" " * padding + title + " " * padding)
    print("=" * length)

def locate_flag(result_string):
    print(f'Extracting flag from {result_string}')
    if type(result_string) == bytes:
        result_string = result_string.decode()
    start = result_string.find('CNS{')
    end = result_string.find('}', start)
    prGreen(f'FLAG >>> {result_string[start:end + 1]} <<<')

def p5_grabber(target):
    target = target.capitalize()
    # A grabber that gets the decoded hex and returns connection
    conn = pwn.remote('cns.csie.org', 44398)
    conn.sendlineafter('>', b'1') # database
    print(f'Grabbing {target}...')
    conn.recvuntil(f'{target}\n'.encode())
    byte_str = bytes.fromhex(conn.recvline().decode().split(':')[1].strip())
    field = None
    if target == "Affine":
        field = conn.recvline().decode().split('\"')[1].strip()
    return conn, byte_str, field

def p6_grabber(target):
    var_dict = {}
    target = target.lower()
    conn = pwn.remote('cns.csie.org', 44399)
    conn.sendlineafter('>', b'1') # database
    print(f'Grabbing {target} database...')
    conn.recvuntil(f'{target}\n'.encode())
    while True:
        line = conn.recvline().decode().strip().replace(' ', '')
        var_split = line.split(':')
        if var_split[0] == 'hint':
            break
        var, val = line.split(':')
        var_dict[var.strip()] = val.strip()
    print('Capturing ciphertext...')
    conn.recvuntil('Database'.encode())
    index = 1
    while True:
        line = conn.recvline().decode().strip().replace(' ', '')
        if target.capitalize() in line:
            break
        index += 1
    conn.sendlineafter('>', str(index).encode())
    cipher_line = conn.recvline().decode().strip().replace(' ', '')
    cipher = cipher_line.split(':')[1]
    if index == 3:
        cipher = cipher[1:-1].split(',')
        var_dict['c1'] = cipher[0]
        var_dict['c2'] = cipher[1]
    else:
        var_dict['c'] = cipher
    print('All variables: ', var_dict)
    return conn, var_dict

def p7_grabber():
    conn = pwn.remote('cns.csie.org', 1337)
    conn.sendlineafter('Your choice: ', b'1') # database
    print('Grabbing c...')
    lines = conn.recvlines(2)
    byte_str = bytes.fromhex(lines[1].decode())
    return conn, byte_str, None
