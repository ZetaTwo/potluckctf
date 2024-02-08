from pwn import *
r = remote('localhost', 1337)
r.sendlineafter(b"SEKURBUT> ", b"flash")

with log.progress("Flashing Firmware") as p:
    for msg in fw.strip().splitlines():
        r.sendafter(b"FLASH>", bytes.fromhex(msg))
        p.status(".")
        status = r.recvline().decode().strip()
        if status == 'done.':
            break
        if status != 'OK.':
            log.error(f"Error: '{status}'")
            exit(1)

    status = r.recvuntil(b"SEKURBUT>", drop=True).decode()

    if "Checksum Failure" in status:
        p.failure(f"{status}")
        exit(1)
    else:
        p.success()

r.sendline(b"boot")
r.interactive()