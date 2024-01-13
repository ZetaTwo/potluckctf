## auxv

* Category: `pwn`
* Solves: `???`

### Executive summary

* On the remote system: `$ cd tmp && cat >pwn.sh <<'END'`.
* Copy the contents of `pwn.sh` from the local system to the remote system.
* Type `END` on the remote and hit enter.
* On the remote system: `$ chmod +x ./pwn.sh && ./pwn.sh`
* The flag should be printed to stdout. With low probability, the exploit will fail; just run `pwn.sh` again.

### Details

This challenge explores the lesser known aspect of kernel-user ELF interaction: [the auxiliary vector](https://man7.org/linux/man-pages/man3/getauxval.3.html).
It is essentially an array consisting of pairs of keys and values (8 bytes each on x86_64), terminated by an entry with a zero key, and [placed on the stack](https://iq.thc.org/how-does-linux-start-a-process) of every userspace program.

The provided kernel patch extends the auxiliary vector with a variable number of key/value pairs (corresponding to open file descriptors) using a custom macro with bounds checks to make sure we don't overflow the vector. However, it [misses a spot](https://elixir.bootlin.com/linux/v6.1.69/source/fs/binfmt_elf.c#L297) where the entry index is incremented unconditionally, leading to an off-by-two error.

Trying to open a large number of files and then spawning a new program from the shell will show you that the bug results in weird userspace crashes:
```
$ for i in $(seq 5 200); do eval "exec $i<>/tmp/0"; done
$ ls -l
Inconsistency detected by ld.so: rtld.c: 1280: rtld_setup_main_map: Assertion `GL(dl_rtld_map).l_libname' failed!
```

Reading the code and/or messing around with gdb reveals that the two 8-byte values that are copied out-of-bounds come from the [counters](https://elixir.bootlin.com/linux/v6.1.69/source/include/linux/mm_types_task.h#L49) that track the numbers of memory pages of various types for the newly created process. One of them ([MM_FILEPAGES](https://elixir.bootlin.com/linux/v6.1.69/source/include/linux/mm_types_task.h#L32)) is always zero, but the other ([MM_ANONPAGES](https://elixir.bootlin.com/linux/v6.1.69/source/include/linux/mm_types_task.h#L33)) can be directly controlled from userspace by increasing the total size of arguments and environment variables that are passed to the process.

This allows you to forge a auxiliary vector entry:
  * With an arbitrary key, provided that it is small enough to be a valid number of pages on the stack of a process. Thankfully, all interesting keys are small.
  * With a zero value, if a 8-byte zero padding is inserted after the end of the auxiliary vector by `STACK_ROUND()` [here](https://elixir.bootlin.com/linux/v6.1.69/source/fs/binfmt_elf.c#L303).
  * With a random value, if no padding is inserted, and the forged key is placed directly before the `AT_RANDOM` [contents](https://elixir.bootlin.com/linux/v6.1.69/source/fs/binfmt_elf.c#L238).

The intended solution is to forge an `AT_SECURE=0` entry. For suid binaries (such as `busybox` used in the initramfs from the challenge), the kernel places `AT_SECURE=1` in the auxiliary vector, which is then used by glibc to disable possibly unsafe features such as the `LD_PRELOAD` variable. Our forged entry will override the one created by the kernel and allow us to execute arbitrary code as root via `LD_PRELOAD=/path/to/evil.so`.