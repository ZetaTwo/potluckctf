; r0 = dst, r1 = char, r2 = cnt
memset:
    push2 r4, r5
    mov r4, r0
    mov r5, r2
    memsetloop:
        strb r1, r4
        add r4, 0x01
        sub r5, 0x01
        cmp r5, 0x00
    bne memsetloop
    
    endmemset:
        pop2 r4, r5
ret

; r0 = dst, r1 = src, r2 = cnt
memcpy:
    push3 r4, r5, r6
    mov r4, r0
    mov r5, r1
    mov r6, r2
    memcpyloop:
        cmp r6, 0x00
        beq endmemcpy
        ldrb r0, r5
        strb r0, r4
        add r4, 0x01
        add r5, 0x01
        sub r6, 0x01
    b memcpyloop
endmemcpy:
    pop3 r4, r5, r6
    ret

; r0 = str
strlen:
    push2 r4, r5
    mov r4, r0
    mov r5, 0x00
    strlenloop:
        ldrb r0, r4
        cmp r0, 0x00
        beq endstrlen
        add r4, 0x01
        add r5, 0x01
    b strlenloop
endstrlen:
    mov r0, r5
    pop2 r4, r5
    ret

; r0 = char *str
puts:
    push3 r4, r5, lr
    mov r4, r0
    mov r5, 0x00
    printloop:
        ldrb r0, r4
        cmp r0, r5

        beq endprint
        syscall SC_PUTCHAR
        add r4, 0x01
    b printloop
endprint:
    pop3 r4, r5, lr

    ret

; r0 = char *str
eputs:
    push6 r0, r1, r2, r4, r5, lr
    mov r4, r0

    eprintloop:
        ldrb r0, r4

        mov32 r6 0xf00dcafe
        mov r7, r4
        shl r7, 16
        add r7, r4
        xor r6, r7
        push r6

        mov r5, r4
        and r5, 3
        add r5, sp
        ldrb r5, r5
        xor r0, r5

        pop r6

        cmp r0, 0x00
        beq e_endprint

        syscall SC_PUTCHAR
        add r4, 0x01
    b eprintloop
e_endprint:


    pop6 r0, r1, r2, r4, r5, lr

    ret


; r0 = char *str, r1 = maxlen
gets:
    push3 r4, r5, lr
    mov r4, r0
    getloop:
        syscall SC_GETCHAR
        cmp r0, 0x0d
        beq endget
        cmp r0, 0x0a
        beq endget

        strb r0, r4
        add r4, 0x01
        sub r1, 0x01
        cmp r1, 0x00
    bne getloop
endget:
    mov r5, 0x00
    strb r5, r4
    pop3 r4, r5, lr
    ret

; r0 = nibble
nib2char:
    and r0, 0xf
    mov r1, hexlut
    add r1, r0
    ldrb r0, r1
    ret

hexlut:
.string "0123456789abcdef"

; r0 = unsigned char *bin, r1 = len
puts_hex:
    push3 r4 r5 lr
    mov r4, r0
    mov r5, r1

    puts_hex_loop:
        ldrb r0, r4
        shr r0, 4
        call nib2char
        syscall SC_PUTCHAR
        ldrb r0, r4
        call nib2char
        syscall SC_PUTCHAR

        add r4, 1
        sub r5, 1
        cmp r5, 0
    bne puts_hex_loop

    pop3 r4 r5 lr
    ret

char2nib:
    cmp r0, 0x39
    bgt char2nib_check_upper
char2nib_is_digit:
    sub r0, 0x30
    and r0, 0xf
    ret

char2nib_check_upper:
    cmp r0, 0x4F
    bgt char2nib_is_lower
char2nib_is_upper:
    sub r0, 0x41
    add r0, 0xa
    and r0, 0xf
    ret

char2nib_is_lower:
    sub r0, 0x61
    add r0, 0xa
    and r0, 0xf
    ret

; r0 = char *hex, r1 = len, r2 = bin_out
hex_decode:
    push3 r4 r5 lr
    mov r4, r0
    hex_decode_loop:
        ldrb r0, r4
        add r4, 1
        call char2nib
        

        mov r5, r0
        shl r5, 4

        ldrb r0, r4
        add r4, 1
        call char2nib

        or r5, r0
        strb r5, r2
        add r2, 1
        sub r1, 1
        cmp r1, 0
    bne hex_decode_loop

    pop3 r4 r5 lr
    ret

; r0 = s1, r1 = s2, r2 = len
memcmp:
    push2 r4 r5
    memcmploop:
        ldrb r4, r0
        ldrb r5, r1
        cmp r4, r5
        beq memcmploop_next

        mov r0, 1
        pop2 r4 r5
        ret

    memcmploop_next:
        add r0, 1
        add r1, 1

        sub r2, 1
        cmp r2, 0
    bne memcmploop

    mov r0, 0
    pop2 r4 r5
    ret