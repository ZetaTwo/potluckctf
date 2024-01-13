from sage.all import *
from pwn import *
import random

p = 0xfffffffffffffffffffffffffffffffeffffffffffffffff
K = GF(p)
a = K(0xfffffffffffffffffffffffffffffffefffffffffffffffc)
b = K(0x64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1)
E = EllipticCurve(K, (a, b))
G = E(0x188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012, 0x07192b95ffc8da78631011ed6b24cdd573f977a11e794811)

R = PolynomialRing(K, 'x')
x = R.gens()[0]

a = K(a)
b = K(2)

# compute discriminant https://crypto.stackexchange.com/a/47228
assert (4 * a ** 3 + 27 * b ** 2) == 0

# offset so that both derivatives vanish https://crypto.stackexchange.com/a/61434
x0 = (-a / K(3)).sqrt()
assert 3 * x0 ** 2 + a == 0

f = x ** 3 + a * x + b
print(f)

f_ = f.subs(x=x + x0)
print(f_, '=', f_.factor())

Px = K(461)  # ensure u is a generator
Py = f(Px).sqrt()
assert f(Px) == Py ** 2

# rem = process("../target/release/abc", stderr=2, env={"FLAG": open('flag.txt').read()})
rem = remote('10.0.3.1', 9999)
Ax, Ay = [int(x) for x in rem.recvline().decode().split(': ')[1].split(', ')]
print(f'A = ({Ax}, {Ay})')

rem.sendline(b'%d, %d' % (Px, Py))
msg = b"Hello, Bob. What are you bringing to the potluck???"
enc_msg = bytes.fromhex(rem.recvline().decode().split()[-1])
print(f'enc_msg = {enc_msg.hex()}')
ABx = K(int.from_bytes(xor(msg[:24], enc_msg[:24]), 'little'))
ABy = K(f(ABx).sqrt())
print(f'AB = ({ABx}, {ABy})')

Cx, Cy = [int(x) for x in rem.recvline().decode().split(': ')[1].split(', ')]
print(f'C = ({Cx}, {Cy})')

enc_flag = bytes.fromhex(rem.recvline().decode().split()[-1])
print(f'enc_flag = {enc_flag.hex()}')

for sig in (-1, 1):
    t = K(3).sqrt()
    P_ = (Px - x0, Py)
    Q_ = (ABx - x0, sig * ABy)

    u = (P_[1] + t * P_[0]) / (P_[1] - t * P_[0])
    v = (Q_[1] + t * Q_[0]) / (Q_[1] - t * Q_[0])
    print(f'Px, Py = ({Px}, {Py})')
    print(f'ABx, ABy = ({ABx}, {ABy})')
    print(f'u, v = ({u}, {v})')

    m = p - 1
    print(facs := factor(m))
    print(u)

    procs = []
    facs = [q for (q, e) in facs]

    for q in facs:
        assert u ** (m // q) != 1


    def brute_log(q):
        uu = u ** (m // q)
        vv = v ** (m // q)
        for i in range(q):
            if uu ** i == vv:
                return i
        assert False


    dd = [brute_log(q) for q in facs[:3]]

    for q in facs[3:]:
        procs.append(process(cmd := f'cado-nfs.py -dlp -ell {q} target={u},{v} {p} -t2', shell=True, stderr=2))
        print(cmd)

    for q, proc in zip(facs[3:], procs):
        print(q, out := proc.recvall().decode().strip())
        lu, lv = [int(x) for x in out.split(",")]
        Kq = GF(q)
        dd.append(int(Kq(lv) / Kq(lu)))

    print(dd)

    d = crt(dd, facs)
    print(d)

    C = E(Cx, Cy)
    AC = C * d
    key = int(AC[0]).to_bytes(24, 'little')
    key = hashlib.sha512(key).digest()
    print(flag := xor(key, enc_flag))
    if flag.startswith(b"potluck"):
        break
