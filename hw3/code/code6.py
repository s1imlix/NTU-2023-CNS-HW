from pwn import *
from grabber import *
from mt19937 import *
from Crypto.Util.number import long_to_bytes
from tqdm import trange

def p1():
    r = remote('cns.csie.org', 6000)
    money = 0
    while money < 20000:
        r.sendlineafter(b'Your choice: ', b'1')    
        player_num = 0
        for i in range(799):
            player_num = (player_num + int(r.recvline().decode().split(' ')[-1])) % 800
        until = 799 - player_num
        until += 800 * (until < 0)
        r.sendlineafter(b'your number: ', str(until).encode())    
        money = int(r.recvline().decode().split(' ')[-1].strip('.G\n'))
        print('Current money:', money)
    r.sendlineafter(b'Your choice: ', b'2')
    locate_flag(r.recvline().decode())

def p2():
    r = remote('cns.csie.org', 6001)
    money = 0
    while money < 20000:
        r.sendlineafter(b'Your choice: ', b'1')
        prev_bet, cur = None, None
        state = [0, 0, 0, 0, 0] 
        check = []
        all_lines = r.recvuntil(b'your number: ')
        lines = all_lines.decode().split('\n')[:-1]
        if len(lines) == 0:
            continue
        prev_bet = int(lines[-1].split(' ')[1].strip('\'s'))
        for l in lines:
            num = int(l.split(' ')[-1])
            check.append(num)
            state.append(untemper(num))
        print('Prev bet:', prev_bet)
        if prev_bet < 630:
            # give up
            print('Give up')
            r.sendline(b'0')
            sleep(0.6)
            continue
        else:
            print('Hit')
            seed_state = backtrace(state, 4)
            prng = mt19937(0)
            prng.set_state(seed_state)
            total, num = 0, []
            for i in range(799):
                num.append(prng.extract_number())
                total = (total + num[-1]) % 800
            until = prev_bet - total
            until += 800 * (until < 0)
            r.sendline(str(until).encode())
            res = r.recvuntil(b'G.\n').decode()
            money = int(res.split(' ')[-1].strip('.G\n'))
            print('Current money:', money)
    r.sendlineafter(b'Your choice: ', b'2')
    locate_flag(r.recvline().decode())

def p3():
    # read output.txt 
    total = 0 
    missing_idx = 194
    nums = []
    with open('output.txt', 'r') as f:
        lines = f.readlines()
        for line in lines:
            if 'number' in line:
                num = int(line.split(' ')[-1].strip())
                nums.append(untemper(int(num)))
    states = [untemper(missing_idx)] + nums[:missing_idx-1] + [0] + nums[missing_idx:]
    states = states[:624]
    
    print('States:', states)
    for i in trange(2**30, 2**32):
        tmp = states 
        tmp[missing_idx] = i
        full_backtrace(tmp)
        try:
            msg = long_to_bytes(tmp[0]).decode()
            if 'CNS' in msg:
                print('Flag:', msg)
                break
        except Exception as e:
            pass
        



if __name__ == '__main__':
    print('P6 Solver')
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
