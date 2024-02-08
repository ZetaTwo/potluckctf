#!/ur/bin/env python3
from pwn import *
import hashlib

s = remote('challenge22.play.potluckctf.com', 31337)

min_hashlen = 0x10

def precompute_hashes(remaining: bytes):
    return {
        hashlib.sha256((bytes([i]) + remaining)[0:min_hashlen]).hexdigest(): i
        for i in range(0x100)
    }

def get_checksum(offset: int, length: int):
    s.sendlineafter(b"SEKURBUT> ", f"checksum {offset:x} {length:x}".encode())
    return s.recvline_contains(b"SHA256(").decode().split()[3]


data = bytes([0]*0x10)

text = s.recvline_contains(b".text")
end = int(text.decode()[19:], 16)-0x10
log.info(f"Starting at {hex(end)}")

with log.progress("Dumping flash") as p:
    for i in range(end, -1, -1):
        hashes = precompute_hashes(data[0:min_hashlen])
        c = hashes[get_checksum(i, min_hashlen)]
        data = bytes([c]) + data
        p.status(f"{100*((end - i) / end):3.0f}% ({end - i}/{end}): {c:x}")
        with open("dumped", "wb+") as f:
            f.truncate()
            f.write(data)
