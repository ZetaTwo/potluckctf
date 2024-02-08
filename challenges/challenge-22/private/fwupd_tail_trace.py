# Use this as fwupd_tail.py to create the trace.
# Uplink and downlink are separate sockets connected to
# UARTs. I used a glasgow for this.

from pwn import *
r = remote('localhost', 1337)

downlink = remote('localhost', '13371')
uplink = remote('localhost', '13372')

dat = r.sendlineafter(b"SEKURBUT> ", b"flash")

downlink.send(dat)
import time
time.sleep(0.01)
uplink.sendline(b"flash")

with log.progress("Flashing Firmware") as p:
    for msg in fw.strip().splitlines():
        dat = r.sendafter(b"FLASH>", bytes.fromhex(msg))
        downlink.send(dat)
        time.sleep(0.002)
        uplink.send(bytes.fromhex(msg))
        p.status(".")
        time.sleep(len(msg) * 0.02/256)
        dat = r.recvline()
        downlink.send(dat)
        status = dat.decode().strip()
        if status == 'done.':
            break
        if status != 'OK.':
            log.error(f"Error: '{status}'")
            exit(1)

    status = r.recvuntil(b"SEKURBUT>", drop=True)
    time.sleep(0.01)
    downlink.send(status)
    status = status.decode()

    if "Checksum Failure" in status:
        p.failure(f"{status}")
        exit(1)
    else:
        p.success()

r.sendline(b"boot")
r.interactive()