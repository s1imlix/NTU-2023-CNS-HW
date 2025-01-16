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

