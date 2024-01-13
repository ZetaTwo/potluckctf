_start:
b main

.include "helper.s"
.include "defs.s"
.include "functions.s"

; r0 = chall_out
generate_challenge:
    push4 r4 r5 r6 r7

    mov r5, r0

    syscall SC_GET_RANDOM32
    mov32 r1, 0xd011face
    mov32 r2, 0xface1e55
    mov32 r3, 0xdeadfa11
    mov32 r4, 0x1eaf1e55
    xor r1, r0
    xor r2, r0
    xor r3, r0
    xor r4, r0
    strw r1, r5
    add r5, 0x4
    strw r2, r5
    add r5, 0x4
    strw r3, r5
    add r5, 0x4
    strw r4, r5

    pop4 r4 r5 r6 r7
ret

; r0 = challenge_bin, r1 = response_out
generate_response:
    ldrw r4, r0
    mov32 r5, 0xc0cac01a
    xor r4, r5
    strw r4, r1
    add r1, 0x4
    add r0, 0x4

    ldrw r4, r0
    mov32 r5, 0xd15ea5e
    xor r4, r5
    strw r4, r1
    add r1, 0x4
    add r0, 0x4

    ldrw r4, r0
    mov32 r5, 0x5caff01d
    xor r4, r5
    strw r4, r1
    add r1, 0x4
    add r0, 0x4

    ldrw r4, r0
    mov32 r5, 0xba5eba11
    xor r4, r5
    strw r4, r1
ret

.equ offs_challenge 0x00
.equ offs_response 0x10
.equ offs_user_response_hex 0x20
.equ offs_user_response_bin 0x50
.equ offs_user_prompt 0x80

main:
    mov r0, 0x200
    sub sp, r0
    mov r4, sp

    call1 puts str_banner

    call1 eputs str_welcome

    mov r0, sp
    add r0, offs_challenge
    call generate_challenge

    call1 eputs str_newline

    mov r0, sp
    add r0, offs_challenge
    mov r1, 0x10
    call puts_hex
    call1 eputs str_newline

    mov r4, sp
    add r4, offs_user_response_hex
    call2 gets r4 0x20

    mov r0, sp
    add r0, offs_user_response_hex
    mov r1, 0x10
    mov r2, sp
    add r2, offs_user_response_bin

    call hex_decode

    mov r0, sp
    add r0, offs_challenge
    mov r1, sp
    add r1, offs_response
    call generate_response

    mov r0, sp
    add r0, offs_user_response_bin
    mov r1, sp
    add r1, offs_response
    mov r2, 0x10
    call memcmp
    cmp r0, 0x00
    beq response_ok

response_bad:
    call1 eputs str_response_bad
    syscall SC_EXIT

response_ok:
    call1 eputs str_response_ok

inputloop:
    call1 eputs str_menu
    call1 eputs str_prompt

    mov r4, sp
    add r4, offs_user_prompt
    call3 memset r4, 0x00, 0x80

    call2 gets r4 0x7f

    ldrb r0, r4

    check_fortunecookie:
    cmp r0, 0x31
    bne check_friendship
    call action_fortune_cookie
    b inputloop

    check_friendship:
    cmp r0, 0x32
    bne check_uptime
    call action_friendship
    b inputloop

    check_uptime:
    cmp r0, 0x33
    bne check_exit
    call action_uptime
    b inputloop

    check_exit:
    cmp r0, 0x34
    bne wrong_choice

    call1 eputs str_goodbye
    syscall SC_EXIT

    wrong_choice:
    call1 eputs str_wrong_choice
b inputloop


ipc_send:
    push lr
    syscall SC_IPC_SENDMSG    
    pop lr
ret

ipc_recv:
    push lr
    syscall SC_IPC_RECVMSG
    pop lr
ret

action_fortune_cookie:
    push lr

    sub sp, 0x80

    mov32 r0, 0xf01dc0de
    strw r0, sp
    mov r0, sp
    mov r1, 0x4
    call ipc_send

    mov r0, sp
    mov r1, 0x0
    mov r2, 0x80
    call memset

    mov r0, sp
    mov r1, 0x80
    call ipc_recv

    call1 eputs str_fortune
    call1 puts sp
    call1 eputs str_newline

    add sp, 0x80

    pop lr
    ret

.equ offs_user_payment 0x40
.equ offs_ipc_msg 0

action_friendship:
    push lr
    sub sp, 0x80

    call1 eputs str_payment
    mov r4, sp
    add r4, offs_user_payment
    call3 memset r4, 0x00, 0x40
    ; vuln
    call2 gets r4 0xff

    mov32 r0, 0xbadf0001
    strw r0, sp

    mov r0, sp
    add r0, 4
    mov r1, sp
    add r1, offs_user_payment
    mov r2, 0x3c
    call memcpy

    mov r0, sp
    mov r1, 0x4
    call ipc_send

    call3 memset sp, 0x00, 0x40

    mov r0, sp
    mov r1, 0x40
    call ipc_recv

    call1 eputs str_friendship
    call1 puts sp

    add sp, 0x80

    pop lr

    ret

action_uptime:
    push lr

    sub sp, 0x80

    call1 eputs str_uptime

    mov32 r0, 0xc01db007
    strw r0, sp
    mov r0, sp
    mov r1, 0x4
    call ipc_send

    mov r0, sp
    add r0, 4
    mov r1, 0x0
    mov r2, 0x70
    call memset

    mov r0, sp
    add r0, 4
    mov r1, 0x70
    call ipc_recv

    mov r0, sp
    add r0, 4
    call puts

    mov r0, str_newline
    call eputs

    add sp, 0x80

    pop lr
    ret

str_banner:
.incbin "intro.txt"
.db 0x00

str_welcome:
.estring "Welcome to Shell's Kitchen, stranger!\n"
.estring "\n"
.estring "Unfortunately, only real chefs are allowed to enter the kitchen.\n"
.estring "Please, prove that you are a real chef by cooking this stew:"
.estringz "\n"

str_menu:
.estring "==== MENU =======================\n"
.estring "1) ask g0rd0n r4ms4y for feedback\n"
.estring "2) request g0rd0n's friendship\n"
.estring "3) check kitchen running time\n"
.estring "4) exit\n"
.estring "=================================\n"
.estringz "\n"

str_prompt:
.estringz "choice> "

str_send:
.estringz "SEND: "

str_newline:
.estringz "\n"

bin_test:
.db 0xde, 0xad, 0xbe, 0xef, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0

str_response_ok:
.estring "well, it looks like you actually might be an elite chef!\n"
.estringz "carry on, my wayward son.\n\n"

str_response_bad:
.estringz "you are not in fact an elite chef, goodbye.\n"

str_wrong_choice:
.estringz "thats not a valid choice.\n\n"

str_goodbye:
.estringz "goodbye my friend.\n"

str_fortune:
.estringz "g0rd0n's feedback: "

str_friendship:
.estringz "the result of your friend request came back: "

str_uptime:
.estringz "kitchen uptime: "

str_payment:
.estringz "how much are you willing to pay for your friendship?\n"