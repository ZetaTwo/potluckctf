#!/usr/bin/env python3

import os
import sys
import struct

from cpu_const import *


def fatal(s):
    print("\x1b[31merror:\x1b[0m %s" % s)
    exit(-1)


def is_label(token):
    return token.endswith(":")


def is_directive(token):
    return token.startswith(".")


def u32_to_list(v):
    return list(reversed([v >> 24, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF]))


def u64_to_list(v):
    return u32_to_list(v & 0xFFFFFFFF) + u32_to_list(v >> 32)


class asm_token:
    def __init__(self, t, v):
        self.type = t
        self.value = v


def asm_nop(**args):
    return [OP_NOP, 0, 0, 0]


def asm_alu(**args):
    tokens = args["tokens"]
    if len(tokens) != 3:
        return None

    alu_op = {
        "add": ALU_ADD,
        "sub": ALU_SUB,
        "mul": ALU_MUL,
        "div": ALU_DIV,
        "and": ALU_AND,
        "or": ALU_OR,
        "xor": ALU_XOR,
        "shl": ALU_SHL,
        "shr": ALU_SHR,
    }

    mnem, dest, src = tokens

    if mnem.value not in alu_op:
        print("invalid alu op")
        return None

    if dest.type != TOKEN_REG:
        print("first operand should be register")
        return None

    if src.type == TOKEN_REG:
        vt = (alu_op[mnem.value] << 4) | SRC_REG
        return [OP_ALU, vt, dest.value, src.value]

    if src.type == TOKEN_IMMEDIATE:
        if src.value > 0xFF:
            print("immediate value too large")
            return None
        vt = (alu_op[mnem.value] << 4) | SRC_IMM
        return [OP_ALU, vt, dest.value, src.value & 0xFF]

    return None


def asm_loadstore(op, tokens):
    if len(tokens) != 3:
        return None

    mnem, src, dest = tokens

    w = {
        "b": 1,
        "h": 2,
        "w": 4,
        "q": 8,
    }[mnem.value[-1]]
    if src.type != TOKEN_REG:
        return None
    if dest.type != TOKEN_REG:
        return None
    return [op, w, src.value, dest.value]


def asm_load(**args):
    tokens = args["tokens"]
    return asm_loadstore(OP_LOAD, tokens)


def asm_store(**args):
    tokens = args["tokens"]
    return asm_loadstore(OP_STORE, tokens)


def asm_mov(**args):
    tokens = args["tokens"]
    if len(tokens) != 3:
        return None

    mnem, dest, src = tokens

    # mov r0, r1
    # mov r0, 0x1234
    if dest.type != TOKEN_REG:
        return None

    if src.type == TOKEN_REG:
        vt = (dest.value << 4) | SRC_REG
        return [OP_MOV, vt, src.value, 0]

    if src.type == TOKEN_IMMEDIATE:
        if src.value > 0xFFFF:
            print("immediate value too large")
            return None
        vt = (dest.value << 4) | SRC_IMM
        return [OP_MOV, vt, src.value & 0xFF, (src.value >> 8) & 0xFF]

    return None


def asm_cmp(**args):
    tokens = args["tokens"]
    if len(tokens) != 3:
        return None

    mnem, ra, rb = tokens

    if ra.type == TOKEN_REG and rb.type == TOKEN_REG:
        return [OP_COMPARE, (CMP_MODE_REG << 4) | 8, ra.value, rb.value]
    elif ra.type == TOKEN_REG and rb.type == TOKEN_IMMEDIATE:
        if rb.value > 0xFF:
            print("immediate value too large")
            return None
        return [OP_COMPARE, (CMP_MODE_IMM8 << 4) | 8, ra.value, rb.value & 0xFF]


def asm_branch(**args):
    tokens = args["tokens"]
    if len(tokens) != 2:
        return None

    mnem, dest = tokens

    t = {
        "b": BRANCH_ALWAYS,
        "beq": BRANCH_EQ,
        "bne": BRANCH_NEQ,
        "blt": BRANCH_LT,
        "bgt": BRANCH_GT,
        "ble": BRANCH_LTE,
        "bge": BRANCH_GTE,
    }[mnem.value]

    if dest.type != TOKEN_IMMEDIATE:
        return None

    pc = args["pc"]

    offset = dest.value - pc
    if offset > 0x7FFF or offset < -0x7FFF:
        print("branch offset too large")
        return None
    offset = offset & 0xFFFF

    return [OP_BRANCH, t, offset & 0xFF, (offset >> 8) & 0xFF]


def asm_syscall(**args):
    tokens = args["tokens"]
    if len(tokens) != 2:
        return None
    mnem, syscall_no = tokens
    if syscall_no.type != TOKEN_IMMEDIATE:
        return None
    return [OP_SYSCALL, syscall_no.value, 0, 0]


def asm_expectf(**args):
    tokens = args["tokens"]

    if len(tokens) != 2:
        return None

    mnem, cmpval = tokens

    if cmpval.type != TOKEN_IMMEDIATE:
        return None

    return [OP_EXPECT, 0, 1, 0] + u64_to_list(cmpval.value)


def asm_expect(**args):
    tokens = args["tokens"]

    if len(tokens) != 3:
        return None

    mnem, dest, cmpval = tokens

    if dest.type != TOKEN_REG or cmpval.type != TOKEN_IMMEDIATE:
        return None

    return [OP_EXPECT, dest.value, 0, 0] + u64_to_list(cmpval.value)


def asm_push(**args):
    tokens = args["tokens"]

    if len(tokens) != 2:
        return None

    mnem, reg = tokens

    if reg.type != TOKEN_REG:
        return None

    return [OP_PUSH, reg.value, 0, 0]


def asm_pop(**args):
    tokens = args["tokens"]

    if len(tokens) != 2:
        return None

    mnem, reg = tokens

    if reg.type != TOKEN_REG:
        return None

    return [OP_POP, reg.value, 0, 0]


def asm_call(**args):
    tokens = args["tokens"]
    pc = args["pc"]

    if len(tokens) != 2:
        return None

    mnem, dest = tokens

    if dest.type == TOKEN_REG:
        return [OP_CALL, CALL_MODE_REG, dest.value, 0]
    elif dest.type == TOKEN_IMMEDIATE:
        offset = dest.value - pc
        if offset > 0x7FFF or offset < -0x7FFF:
            print("branch offset too large")
            return None
        offset = offset & 0xFFFF
        return [OP_CALL, CALL_MODE_REL, offset & 0xFF, (offset >> 8) & 0xFF]

    return None


def asm_ret(**args):
    tokens = args["tokens"]
    if len(tokens) != 1:
        return None
    return [OP_RET, 0, 0, 0]


def resolve_label(label):
    if label not in labels:
        fatal(f"Unknown label {label}")
    return labels[label]


def get_reg(token):
    regs = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "sp", "lr", "pc"]
    if token in regs:
        return regs.index(token)
    return None


def parse_token(token):
    if get_reg(token) is not None:
        return (TOKEN_REG, get_reg(token))

    t = TOKEN_IMMEDIATE

    if token.startswith("0x"):
        v = int(token[2:], 16)
    elif token.startswith("0b"):
        v = int(token[2:], 2)
    elif token.startswith("'") and token.endswith("'"):
        v = ord(token[1:-1])
    elif token in labels.keys():
        v = resolve_label(token)
    else:
        v = eval(token)

    return (t, v)


def expand_includes(lines, rootdir=""):
    newlines = []
    for line in lines:
        tokens = line.split()
        if len(tokens) == 0:
            continue
        if tokens[0] == ".include":
            if len(tokens) != 2:
                fatal(f"Invalid include @ line {line_no}")
            filename = rootdir + "/" + eval(tokens[1])
            if not os.path.exists(filename):
                fatal(f"File {filename} does not exist")
            newlines += open(filename, "r").readlines()
        else:
            newlines.append(line)
    return newlines


def expand_macros(lines):
    line_no = 0
    macros = {}
    newlines = []
    while line_no < len(lines):
        line = lines[line_no]
        tokens = line.split()
        if len(tokens) == 0:
            line_no += 1
            continue

        if tokens[0] == ".macro":
            if len(tokens) != 2:
                fatal(f"Invalid macro @ line {line_no}")
            name = tokens[1]
            macro = []
            while True:
                line_no += 1
                line = lines[line_no]
                if line.strip() == ".endmacro":
                    line_no += 1
                    break
                macro.append(line)
            macros[name] = macro
        elif tokens[0] in macros:
            macro = macros[tokens[0]]
            args = [x.rstrip(",") for x in tokens[1:]]
            for macro_line in macro:
                for i, arg in enumerate(args):
                    macro_line = macro_line.replace(f"${i+1}", arg)
                newlines.append(macro_line)
            line_no += 1
        else:
            newlines.append(line)
            line_no += 1
    return newlines


def directive_size(**args):
    tokens = args["tokens"]
    line = args["line"]
    directive = tokens[0]

    if directive == ".db":
        return len(tokens[1:])
    elif directive == ".dw":
        return len(tokens[1:]) * 2
    elif directive == ".dd":
        return len(tokens[1:]) * 4
    elif directive == ".dq":
        return len(tokens[1:]) * 8
    elif directive in [".align", ".space"]:
        return int(tokens[1])
    elif directive in [".estring", ".string"]:
        s = line.split(None, 1)[1]
        return len(eval(s))
    elif directive in [".estringz", ".stringz"]:
        s = line.split(None, 1)[1]
        return len(eval(s)) + 1
    elif directive in [".equ", ".execdata"]:
        return 0
    elif directive == ".incbin":
        return os.path.getsize(eval(tokens[1]))
    else:
        fatal(f"Unknown directive {tokens[0]}")


def str_crypt(s, pc, null_terminate=False):
    o = b""
    for i, c in enumerate(s):
        k = struct.pack("<L", 0xF00DCAFE ^ ((pc + i) << 16 | (pc + i)))
        o += bytes([ord(c) ^ k[(pc + i) % 4]])
    if null_terminate:
        k = struct.pack("<L", 0xF00DCAFE ^ ((pc + len(s)) << 16 | (pc + len(s))))
        o += bytes([0 ^ k[(pc + len(s)) % 4]])

    return o


def sym(s):
    s = s.rstrip(",")
    if s in symbolmap:
        return int(symbolmap[s], 0)
    if s in labels:
        return labels[s]
    else:
        return int(s, 0)


def directive_asm(**args):
    tokens = args["tokens"]
    line = args["line"]
    directive = tokens[0]

    if directive == ".db":
        return [sym(x) for x in tokens[1:]]
    elif directive == ".dw":
        return [sym(x) for x in tokens[1:]]
    elif directive == ".dd":
        o = []
        for x in tokens[1:]:
            o += u32_to_list(sym(x))
        return o
    elif directive == ".dq":
        return [sym(x) for x in tokens[1:]]
    elif directive in [".align", ".space"]:
        return [0] * int(tokens[1])
    elif directive == ".string":
        s = line.split(None, 1)[1]
        return [ord(x) for x in eval(s)]
    elif directive == ".estring":
        s = line.split(None, 1)[1]
        return [x for x in str_crypt(eval(s), args["pc"])]
    elif directive == ".stringz":
        s = line.split(None, 1)[1]
        return [ord(x) for x in eval(s)] + [0]
    elif directive == ".estringz":
        s = line.split(None, 1)[1]
        return [x for x in str_crypt(eval(s), args["pc"], True)]
    elif directive in [".equ", ".execdata"]:
        return []
    elif directive == ".incbin":
        return [x for x in open(eval(tokens[1]), "rb").read()]
    else:
        fatal(f"Unknown directive {tokens[0]}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: asm.py <input> <output>")
        sys.exit(1)

    infile = sys.argv[1]
    outfile = sys.argv[2]

    lines = [line.strip() for line in open(infile, "r").readlines()]

    symbolmap = {}

    exec_data = False

    lines = expand_includes(lines, os.path.dirname(infile))
    lines = expand_macros(lines)
    for line_no, line in enumerate(lines):
        tokens = line.split()
        if len(tokens) == 0:
            continue
        if tokens[0] == ".equ":
            if len(tokens) != 3:
                fatal(f"Invalid .equ @ line {line_no}")
            symbolmap[tokens[1]] = tokens[2]

    pc = 0
    labels = {}

    opcodes = {
        "nop": asm_nop,
        "add": asm_alu,
        "sub": asm_alu,
        "and": asm_alu,
        "or": asm_alu,
        "xor": asm_alu,
        "shl": asm_alu,
        "shr": asm_alu,
        "mul": asm_alu,
        "div": asm_alu,
        "ldrb": asm_load,
        "ldrh": asm_load,
        "ldrw": asm_load,
        "ldrq": asm_load,
        "strb": asm_store,
        "strh": asm_store,
        "strw": asm_store,
        "strq": asm_store,
        "mov": asm_mov,
        "cmp": asm_cmp,
        "b": asm_branch,
        "beq": asm_branch,
        "bne": asm_branch,
        "bgt": asm_branch,
        "bge": asm_branch,
        "blt": asm_branch,
        "ble": asm_branch,
        "exp": asm_expect,
        "expf": asm_expectf,
        "syscall": asm_syscall,
        "push": asm_push,
        "pop": asm_pop,
        "call": asm_call,
        "ret": asm_ret,
    }

    # collect labels
    for line_no, line in enumerate(lines):
        if line.startswith(";"):
            continue
        tokens = line.split()
        if len(tokens) == 0:
            continue

        if is_label(tokens[0]):
            label = tokens[0][:-1]
            if label in labels:
                fatal(f"Duplicate label {label} @ line {line_no}")
            labels[label] = pc
            continue

        if is_directive(tokens[0]):
            pc += directive_size(tokens=tokens, line=line)
            continue

        insn = tokens[0].lower()
        if insn not in opcodes:
            fatal(f"Unknown instruction {insn} @ line {line_no}")

        if insn == "exp":
            pc += 8

        pc += 4

    # assemble opcodes
    pc = 0
    b = b""
    for line_no, line in enumerate(lines):
        if line.startswith(";"):
            continue
        tokens = line.split()
        if len(tokens) == 0:
            continue

        if is_label(tokens[0]):
            continue

        if is_directive(tokens[0]):
            if tokens[0] == ".execdata":
                exec_data = True
            b += bytes(directive_asm(tokens=tokens, line=line, pc=pc))
            pc += directive_size(tokens=tokens, line=line)
            continue

        # convert tokens
        mnemonic = tokens[0].lower()
        newtok = [asm_token(TOKEN_INST, mnemonic)]
        for token in tokens[1:]:
            token = token.rstrip(",")
            if token in symbolmap:
                token = symbolmap[token]
            try:
                t, v = parse_token(token)
            except:
                fatal(f"Invalid token {token} @ line {line_no} ({line.strip()})")
            newtok.append(asm_token(t, v))

        v = opcodes[mnemonic](tokens=newtok, pc=pc)
        if v is None:
            fatal(f"Invalid instruction @ line {line_no} --> {line.strip()}")

        for i in range(0, len(v), 4):
            vv = (v[i + 0] << 24) | (v[i + 1] << 16) | (v[i + 2] << 8) | v[i + 3]
            b += struct.pack(">I", vv)

        pc += len(v)

    with open(outfile, "wb") as f:
        hdr = b"UNICORN\x00"
        hdr += struct.pack("<H", 2)
        hdr += struct.pack("<HHH", 0, 0x8000, PROT_READ | PROT_EXEC)
        prot = PROT_READ | PROT_WRITE
        if exec_data:
            prot |= PROT_EXEC
        hdr += struct.pack("<HHH", 0x8000, 0x8000, prot)
        f.write(hdr + b)
