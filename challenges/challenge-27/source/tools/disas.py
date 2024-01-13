#!/usr/bin/env python3

from cpu_const import *
from struct import unpack
import sys

REGS = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "sp", "lr", "pc"]

if __name__ == "__main__":
    data = open(sys.argv[1], "rb").read()

    num_mapping = unpack("<H", data[8:10])[0]
    text_base = unpack("<H", data[10:12])[0]

    code_start = 10 + num_mapping * 6
    code = data[code_start:]

    pc = 0
    while pc < len(code) - 4:
        opcode = code[pc]
        b = code[pc + 1]
        c = code[pc + 2]
        d = code[pc + 3]
        cd = (d << 8) | c
        line = "%04x: %02x %02x %02x %02x -- " % (text_base + pc, opcode, b, c, d)

        if opcode == OP_NOP:
            line += "nop"
        elif opcode == OP_BRANCH:
            if b > 6:
                line += "???"
            else:
                line += ["b", "beq", "bne", "blt", "bgt", "ble", "bge"][b]
                line += " 0x%04x" % (
                    text_base + pc + (cd if cd < 0x8000 else cd - 0x10000)
                )
        elif opcode == OP_LOAD:
            if b not in [1, 2, 4, 8]:
                line += "???"
            else:
                line += {1: "ldrb", 2: "ldrh", 4: "ldrw", 8: "ldrq"}[b]
                line += " %s, [%s]" % (REGS[c], REGS[d])
        elif opcode == OP_STORE:
            if b not in [1, 2, 4, 8]:
                line += "???"
            else:
                line += {1: "strb", 2: "strh", 4: "strw", 8: "strq"}[b]
                line += " %s, [%s]" % (REGS[c], REGS[d])
        elif opcode == OP_ALU:
            if (b >> 4) > 8:
                line += "???"
            else:
                line += ["add", "sub", "mul", "div", "and", "or", "xor", "shl", "shr"][
                    b >> 4
                ]
                if b & 0xF == SRC_REG:
                    if c < 11 and d < 11:
                        line += " %s, %s" % (REGS[c], REGS[d])
                    else:
                        line += " ???"
                elif b & 0xF == SRC_IMM:
                    if c < 11:
                        line += " %s, 0x%02x" % (REGS[c], d)
                    else:
                        line += " ???"
        elif opcode == OP_SYSCALL:
            line += "syscall 0x%x" % (b)
        elif opcode == OP_COMPARE:
            w = b & 0xF
            if w not in [1, 2, 4, 8]:
                line += "???"
            else:
                line += {1: "cmpb", 2: "cmph", 4: "cmpw", 8: "cmpq"}[w]
                if b >> 4 == CMP_MODE_REG:
                    line += " %s, %s" % (REGS[c], REGS[d])
                elif b >> 4 == CMP_MODE_IMM8:
                    line += " %s, 0x%02x" % (REGS[c], d)
        elif opcode == OP_MOV:
            r = b >> 4
            if b & 0xF == SRC_REG:
                line += "mov %s, %s" % (REGS[r], REGS[c])
            elif b & 0xF == SRC_IMM:
                line += "mov %s, 0x%04x" % (REGS[r], cd)
            else:
                line += "???"
        elif opcode == OP_PUSH:
            if b > 10:
                line += "???"
            else:
                line += "push %s" % (REGS[b])
        elif opcode == OP_POP:
            if b > 10:
                line += "???"
            else:
                line += "pop %s" % (REGS[b])
        elif opcode == OP_CALL:
            if b == CALL_MODE_REL:
                line += "call 0x%04x" % (
                    text_base + pc + (cd if cd < 0x8000 else cd - 0x10000)
                )
            elif b == CALL_MODE_REG:
                line += "call %s" % (REGS[c])
            else:
                line += "???"
        elif opcode == OP_RET:
            line += "ret"
        elif opcode == OP_EXPECT:
            line += "expect"
        else:
            line += "???"

        print(line)

        pc += 4
