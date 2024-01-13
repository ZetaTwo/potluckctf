### Thank you to fellow pjsker legoclones, he was the one who made this bytecode vm!
### IMPORTS ###
import sys


### READ INSTRUCTIONS ###
# read file
if len(sys.argv) != 2:
    print('Usage: python3 legoasm.py <filename>')
    exit(1)

with open(sys.argv[1], 'rb') as f:
    contents = f.read()

# split up contents
magic_bytes = contents[:4]
length = int.from_bytes(contents[4:8], byteorder='little')
instructions = contents[8:]

# check magic bytes
if magic_bytes != b'LEGO':
    print('Invalid executable')
    exit(1)



### INITIALIZATIONS ###
stack = bytearray([])
registers = [0]*4
pc = 0
buffer = ''



### INSTRUCTIONS ###
# MOV 
# 
# bits 0-3  : opcode
# bit 4     : 0=register, 1=immediate
# bits 5-8  : destination register
# bits 9-16 : source register or immediate value
# 
MOV = 0b000
def mov():
    # global
    global pc
    global registers
    global stack

    # parse
    immediate = bool((instructions[pc] & 0b00010000) >> 4)
    dest_reg = (instructions[pc] & 0b00001111)

    # verify
    if dest_reg not in range(4):
        print('Invalid register')
        exit(1)
    if not immediate:
        try:
            src_reg = (instructions[pc+1] & 0b11110000) >> 4
            if src_reg not in range(4):
                print('Invalid register')
                exit(1)
        except IndexError:
            print('Invalid length')
            exit(1)

    # execute
    if immediate:
        value = instructions[pc+1]
        registers[dest_reg] = value
    else:
        registers[dest_reg] = registers[src_reg]

    # increment
    pc += 2



# ADD
# 
# bits 0-3  : opcode
# bit 4     : 0=register, 1=immediate
# bits 5-8  : destination register
# bits 9-16 : source register or immediate value
# 
ADD = 0b001
def add():
    # global
    global pc
    global registers
    global stack

    # parse
    immediate = bool((instructions[pc] & 0b00010000) >> 4)
    dest_reg = (instructions[pc] & 0b00001111)

    # verify
    if dest_reg not in range(4):
        print('Invalid register')
        exit(1)
    if not immediate:
        try:
            src_reg = (instructions[pc+1] & 0b11110000) >> 4
            if src_reg not in range(4):
                print('Invalid register')
                exit(1)
        except IndexError:
            print('Invalid length')
            exit(1)

    # execute
    if immediate:
        value = instructions[pc+1]
        registers[dest_reg] += value
    else:
        registers[dest_reg] += registers[src_reg]

    # increment
    pc += 2



# CMP
# 
# bits 0-3  : opcode
# bit 4     : 0
# bits 5-8  : destination register
# 
CMP = 0b010
def cmp():
    # global
    global pc
    global registers
    global stack

    # parse
    dest_reg = (instructions[pc] & 0b00001111)

    # verify
    if dest_reg not in range(4):
        print('Invalid register')
        exit(1)
    if ((instructions[pc] & 0b00010000) >> 4) != 0:
        print('Invalid opcode')
        exit(1)

    # execute
    value = registers[dest_reg]
    if value != 0:
        print('Wrong')
        exit(1)

    # increment
    pc += 1



# POP
# 
# bits 0-3  : opcode
# bit 4     : 0
# bits 5-8  : destination register
# 
POP = 0b011
def pop():
    # global
    global pc
    global registers
    global stack

    # parse
    dest_reg = (instructions[pc] & 0b00001111)

    # verify
    if dest_reg not in range(4):
        print('Invalid register')
        exit(1)
    if ((instructions[pc] & 0b00010000) >> 4) != 0:
        print('Invalid opcode')
        exit(1)

    # execute
    value = stack.pop()
    registers[dest_reg] = value

    # increment
    pc += 1



# PSH
# 
# bits 0-3  : opcode
# bit 4     : 0
# bits 5-8  : destination register
# 
PSH = 0b100
def psh():
    # global
    global pc
    global registers
    global stack

    # parse
    dest_reg = (instructions[pc] & 0b00001111)

    # verify
    if dest_reg not in range(4):
        print('Invalid register')
        exit(1)
    if ((instructions[pc] & 0b00010000) >> 4) != 0:
        print('Invalid opcode')
        exit(1)

    # execute
    value = registers[dest_reg]
    stack.append(value)

    # increment
    pc += 1



# INP
# 
# bits 0-3  : opcode
# bit 4     : 0
# bits 5-8  : destination register
# 
INP = 0b101
def inp():
    # global
    global pc
    global registers
    global stack
    global buffer

    # parse
    dest_reg = (instructions[pc] & 0b00001111)

    # verify
    if dest_reg not in range(4):
        print('Invalid register')
        exit(1)
    if ((instructions[pc] & 0b00010000) >> 4) != 0:
        print('Invalid opcode')
        exit(1)

    # execute
    if len(buffer) == 0:
        buffer = input().encode() # makes input a number
    value = buffer[0]
    buffer = buffer[1:]

    registers[dest_reg] = value

    # increment
    pc += 1



# XOR
# 
# bits 0-3  : opcode
# bit 4     : 0=register, 1=immediate
# bits 5-8  : destination register
# bits 9-16 : source register or immediate value
# 
XOR = 0b110
def xor():
    # global
    global pc
    global registers
    global stack

    # parse
    immediate = bool((instructions[pc] & 0b00010000) >> 4)
    dest_reg = (instructions[pc] & 0b00001111)

    # verify
    if dest_reg not in range(4):
        print('Invalid register')
        exit(1)
    if not immediate:
        try:
            src_reg = (instructions[pc+1] & 0b11110000) >> 4
            if src_reg not in range(4):
                print('Invalid register')
                exit(1)
        except IndexError:
            print('Invalid length')
            exit(1)

    # execute
    if immediate:
        value = instructions[pc+1]
        registers[dest_reg] ^= value
    else:
        registers[dest_reg] ^= registers[src_reg]

    # increment
    pc += 2



# OUT
# 
# bits 0-3  : opcode
# bit 4     : 0
# bits 5-8  : destination register
# 
OUT = 0b111
def out():
    # global
    global pc
    global registers
    global stack

    # parse
    dest_reg = (instructions[pc] & 0b00001111)

    # verify
    if dest_reg not in range(4):
        print('Invalid register')
        exit(1)
    if ((instructions[pc] & 0b00010000) >> 4) != 0:
        print('Invalid opcode')
        exit(1)

    # execute
    value = registers[dest_reg]
    print(chr(value), end='')

    # increment
    pc += 1



### PARSE INSTRUCTIONS ###
while pc < length:
    try:
        opcode = (instructions[pc] & 0b11100000) >> 5
    except IndexError:
        print('Invalid length')
        exit(1)

    ### DEBUG ###
    print("=========================================")
    print('pc: ' + str(pc))
    print('opcode: ' + str(opcode))
    print('registers: ' + str(registers))
    print('stack: ' + str(stack))
    print('buffer: ' + str(buffer))
    print("=========================================")


    if opcode == MOV:
        mov()
    elif opcode == ADD:
        add()
    elif opcode == CMP:
        cmp()
    elif opcode == POP:
        pop()
    elif opcode == PSH:
        psh()
    elif opcode == INP:
        inp()
    elif opcode == XOR:
        xor()
    elif opcode == OUT:
        out()
    else:
        print('Invalid opcode')
        exit(1)



    print("================= END ========================")
    print('pc: ' + str(pc))
    print('opcode: ' + str(opcode))
    print('registers: ' + str(registers))
    print('stack: ' + str(stack))
    print('buffer: ' + str(buffer))
    print("=========================================")
