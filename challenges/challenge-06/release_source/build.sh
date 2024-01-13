#!/bin/bash

# Centralized build script because having Makefiles for everything was too annoying

# Delete old artifacts

rm -r build

# Start building

mkdir tmp
mkdir tmp/kernel
mkdir build

# Compile Kernel

nasm -fbin kernel/netboot.asm -o tmp/kernel/netboot.bin
nasm -felf kernel/kernel_entry.asm -o tmp/kernel/kernel_entry.o

gcc -g -m32 -fno-pie -fno-stack-protector -ffreestanding -nodefaultlibs -c kernel/kernel.c -o tmp/kernel/kernel.o
gcc -g -m32 -fno-pie -fno-stack-protector -ffreestanding -nodefaultlibs -c kernel/a20.c -o tmp/kernel/a20.o
gcc -g -m32 -fno-pie -fno-stack-protector -ffreestanding -nodefaultlibs -c kernel/print.c -o tmp/kernel/print.o
gcc -g -m32 -fno-pie -fno-stack-protector -ffreestanding -nodefaultlibs -c kernel/pxe.c -o tmp/kernel/pxe.o
gcc -g -m32 -fno-pie -fno-stack-protector -ffreestanding -nodefaultlibs -c kernel/helper.c -o tmp/helper.o

ld -m elf_i386 -o tmp/kernel/kernel_linked.bin -Ttext 0x8000 tmp/kernel/kernel_entry.o tmp/kernel/kernel.o tmp/kernel/print.o tmp/kernel/a20.o tmp/helper.o tmp/kernel/pxe.o
objcopy -O binary -j .text -j .data -j .rdata -j .rodata tmp/kernel/kernel_linked.bin tmp/kernel/kernel.bin

cat tmp/kernel/netboot.bin tmp/kernel/kernel.bin > build/hypertextos

# Compile Drivers

mkdir tmp/drivers
mkdir build/e410c307

# Compile JS Driver

mkdir tmp/drivers/js

nasm -felf drivers/js/driver_entry.asm -o tmp/drivers/js/driver_entry.o
gcc -g -m32 -fno-pie -fno-stack-protector -ffreestanding -nodefaultlibs -c drivers/js/js_driver.c -o tmp/drivers/js/js_driver.o
gcc -g -m32 -fno-pie -fno-stack-protector -ffreestanding -nodefaultlibs -c drivers/js/elk/elk.c -o tmp/drivers/js/elk.o
ld -m elf_i386 -o tmp/drivers/js/driver_linked.bin -Ttext 0x100000 tmp/drivers/js/driver_entry.o tmp/drivers/js/js_driver.o tmp/helper.o tmp/drivers/js/elk.o

objcopy -O binary -j .text -j .data -j .rdata -j .rodata tmp/drivers/js/driver_linked.bin tmp/drivers/js/driver.bin
cat tmp/drivers/js/driver.bin > build/e410c307/0bafe770

# Compile VM Driver

mkdir tmp/drivers/vm


nasm -felf drivers/vm/driver_entry.asm -o tmp/drivers/vm/driver_entry.o
gcc -g -m32 -fno-pie -fno-stack-protector -ffreestanding -nodefaultlibs -c drivers/vm/vm_driver.c -o tmp/drivers/vm/vm_driver.o
ld -m elf_i386 -o tmp/drivers/vm/driver_linked.bin -Ttext 0x200000 tmp/drivers/vm/driver_entry.o tmp/drivers/vm/vm_driver.o tmp/helper.o 
objcopy -O binary -j .text -j .data -j .rdata -j .rodata tmp/drivers/vm/driver_linked.bin tmp/drivers/vm/driver.bin

cat tmp/drivers/vm/driver.bin > build/e410c307/c03bc6b3


# Build VM Stuff

mkdir tmp/vm
mkdir build/0bbfd16a


java -jar vm/Obfuscat-v1.1.jar builder Verify -data '"6c523086"' --output tmp/vm/verify.fbin
java -jar vm/Obfuscat-v1.1.jar obfuscate Flatten  -input tmp/vm/verify.fbin --output tmp/vm/verify-2.fbin
java -jar vm/Obfuscat-v1.1.jar compile VM -input tmp/vm/verify-2.fbin --output build/0bbfd16a/d1475a3a

javac --release 8 vm/RC4.java -d tmp/vm
java -jar vm/Obfuscat-v1.1.jar builder Class -path tmp/vm/RC4.class -entry entry -merge --output tmp/vm/RC4.fbin
java -jar vm/Obfuscat-v1.1.jar obfuscate Flatten  -input tmp/vm/RC4.fbin --output tmp/vm/RC4-2.fbin
java -jar vm/Obfuscat-v1.1.jar compile VM -input tmp/vm/RC4-2.fbin --output build/0bbfd16a/e82bed4f

javac --release 8 vm/AES128.java -d tmp/vm
java -jar vm/Obfuscat-v1.1.jar builder Class -path tmp/vm/AES128.class -entry entry -merge --output tmp/vm/AES128.fbin
java -jar vm/Obfuscat-v1.1.jar obfuscate Flatten  -input tmp/vm/AES128.fbin --output tmp/vm/AES128-2.fbin
java -jar vm/Obfuscat-v1.1.jar compile VM -input tmp/vm/AES128-2.fbin --output build/0bbfd16a/054d7b96


gcc -g -m32 vm/test_vm.c -o tmp/vm/test_vm
./tmp/vm/test_vm

# Copy Web Programs and encrypt them

mkdir build/15c93851
python3 web/rc4js.py web/app.js build/15c93851/844af54e
python3 web/rc4js.py web/encrypt.js build/15c93851/3019d862
python3 web/rc4js.py web/check.js build/15c93851/8d5e5184
python3 web/rc4js.py web/flag.js build/15c93851/6c523086
python3 web/rc4js.py web/verify.js build/15c93851/cd3f3a04

echo -e "#!ipxe\n\r\n\rboot hypertextos" > build/index.html
# Delete tmp stuff

rm -r tmp

# Run Qemu
cd build

#qemu-system-i386 -boot n -device e1000,netdev=mynet0,mac=52:54:00:12:34:56 -netdev user,id=mynet0,net=192.168.76.0/24,dhcpstart=192.168.76.9,tftp=./,bootfile=hypertextos --serial stdio -object filter-dump,id=mynet0,netdev=mynet0,file=networkDump.dat
#qemu-system-i386 -boot n -device e1000,netdev=mynet0 -netdev user,id=mynet0,bootfile=http://localhost:8000