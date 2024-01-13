from Crypto.Util.number import long_to_bytes as ltb
from pwn import *

blocks = 8
conn = process(['python3', 'final.py'])
# conn = remote('127.0.0.1', int(31337))

conn.recvline()
p = int(conn.recvline()[2:])
K = GF(p)

eqns = []
targetVec = [K(0) for _ in range(2*blocks)]
for blkidx in range(2 * blocks):
	coeffs = [K(0) for _  in range(2*blocks)]
	conn.recvuntil(b'> ')
	conn.sendline(b'2')
	ct = int(conn.recvline()[4:])
	iv = int(conn.recvline()[4:])
	key = list(map(int, conn.recvline()[5:].split(b',')))
	for idx in range(blocks):
		if (iv >> idx) & 1:
			coeffs[idx + blocks] = key[idx]
		else:
			coeffs[idx] = key[idx]
	eqns.append(coeffs)
	targetVec[blkidx] = ct

M = Matrix(K, eqns)
print(M)
S = M.solve_right(vector(targetVec))
print(S)

soln = 0
for elem in S[:blocks][::-1]:
	soln *= p
	soln += int(elem)

print(ltb(soln))

print(M.nullity())
