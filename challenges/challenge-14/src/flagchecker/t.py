E = 1
if E:
    M = b""
C=exit
P=bool
N=IndexError
I=range
E=print
C=exit
l = []
F=1
h=""
Q=bytearray([])
H=[0]*4
A=0
U=0
V=1
W=2
X=3
Y=4
Z=5
a=6
b=7
O=open("instructions.bin", "rb").read()
S=O[:4]
T=int.from_bytes(O[4:8],"little")
D=list(O[8:])
R = 0
if S!=b"LEGO":C(1)
L = ""
from types import CodeType

m = CodeType(0, 0, 0, 0, 0, 0x00000040, m_bytecode, m_co_consts, m_co_names, (), "<string>", "main", "main", 1, b"", b"", (), ())

while D:
    exec(m)

if E:
    if F:
        print("Accepted!")
    else:
        print("Rejected!")