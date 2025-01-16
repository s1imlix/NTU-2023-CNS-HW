from stem.descriptor.hidden_service import HiddenServiceDescriptorV3, HiddenServiceDescriptorV2
from sympy.ntheory.modular import crt
from Crypto.Util.number import long_to_bytes
from sage.all import discrete_log, GF
from grabber import locate_flag
import subprocess
import socks
import socket
import os
import sys

FNULL = open(os.devnull, 'w') # /dev/null


def retract_open_port(data):
    """
    data: nmap outputs decoded, stripped, and split by '\n'
    """
    port_list = [i for i in data if ("tcp" in i or "udp" in i) and "closed" not in i]
    for i in port_list:
        info = i.split(' ')
        print(f'{info[0]} => {info[2]}')


def attack(p, a2, a4, a6, Gx, Gy, Px, Py):
    """
    Solves the discrete logarithm problem on a singular curve (y^2 = x^3 + a2 * x^2 + a4 * x + a6).
    :param p: the prime of the curve base ring
    :param a2: the a2 parameter of the curve
    :param a4: the a4 parameter of the curve
    :param a6: the a6 parameter of the curve
    :param Gx: the base point x value
    :param Gy: the base point y value
    :param Px: the point multiplication result x value
    :param Py: the point multiplication result y value
    :return: l such that l * G == P
    """
    x = GF(p)["x"].gen()
    f = x ** 3 + a2 * x ** 2 + a4 * x + a6
    roots = f.roots()

    # Singular point is a cusp.
    if len(roots) == 1:
        alpha = roots[0][0]
        u = (Gx - alpha) / Gy
        v = (Px - alpha) / Py
        return int(v / u)

    # Singular point is a node.
    if len(roots) == 2:
        if roots[0][1] == 2:
            alpha = roots[0][0]
            beta = roots[1][0]
        elif roots[1][1] == 2:
            alpha = roots[1][0]
            beta = roots[0][0]
        else:
            raise ValueError("Expected root with multiplicity 2.")

        t = (alpha - beta).sqrt()
        u = (Gy + t * (Gx - alpha)) / (Gy - t * (Gx - alpha)) # P after isomorphism
        v = (Py + t * (Px - alpha)) / (Py - t * (Px - alpha))
        return u, int(v.log(u))

    raise ValueError(f"Unexpected number of roots {len(roots)}.")


file_path = 'tor.pub'
bytes_data = None
with open(file_path, 'rb') as file: 
    bytes_data = file.read()

addr = HiddenServiceDescriptorV3.address_from_identity_key(bytes_data[32:]) # Only take the bytes
print('Address: ', addr)

"""
Port scanning

procs = []
num_of_proc = 85
proc_port = 65535//num_of_proc
# Start subprocesses that nmap scan all ports 
for i in range(1, num_of_proc):
    port_range = '{}-{}'.format((i-1)*proc_port+1, i*proc_port)
    print('Subprocess created for port range: ', port_range)
    procs.append(subprocess.Popen(['proxychains', 'nmap', '-n', '-Pn', '-sT', '-p', port_range, addr], stdout=subprocess.PIPE, stderr=FNULL))

i = 1
for proc in procs:
    print('Waiting for process', i)
    i += 1
    retract_open_port(proc.communicate()[0].decode().strip().split('\n'))
"""

socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)

print('Collecting congruence...')
cong_n = []
cong_c = []
sys.set_int_max_str_digits(10000)

for i in range(10):
    s = socks.socksocket()
    s.connect((addr, 11729))
    cipher = s.recv(1024).decode().split('\n')[-4:-2]
    curve = cipher[0].split(' ')
    eq = cipher[1].split(' ')
    a2, a4, a6, p = 0, int(curve[4].strip('x')), int(curve[6].strip()), int(curve[8].strip()) 
    Gx, Gy, Px, Py = int(eq[2].strip('(,')), int(eq[3].strip('),')), int(eq[8].strip('(,')), int(eq[9].strip(')'))
    print(f'Curve: y^2 = x^3 + {a2}x^2 + {a4}x + {a6} (mod {p})')
    print(f'G = ({Gx}, {Gy})')
    print(f'P = ({Px}, {Py})')
    psiP, flag = attack(p, a2, a4, a6, Gx, Gy, Px, Py)
    new_order = discrete_log(1/psiP, psiP) + 1
    cong_n.append(new_order)
    cong_c.append(flag)
    print(f'x mod {new_order} = {flag}')
    s.close()
    # Flag after isomorphism

mp, _ = crt(cong_n, cong_c)
locate_flag(long_to_bytes(mp).decode())
