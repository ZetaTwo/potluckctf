_start:

.execdata

b main

.include "helper.s"
.include "defs.s"
.include "functions.s"

.equ IPC_MSG_FORTUNE_COOKIE 0xf01dc0de
.equ IPC_MSG_OTHER 0xdeadbeef

action_fortune_cookie:
    push lr

    syscall SC_GET_RANDOM32
    and r0, 0x7
    shl r0, 2

    mov r1, cookies
    add r1, r0
    ldrw r0, r1
    mov r4, r0
    call strlen
    add r0, 1

    mov r1, r0
    mov r0, r4
    syscall SC_IPC_SENDMSG

    pop lr
    ret

action_friendship:
    push lr

    mov r0, str_nosale
    call strlen

    mov r1, r0
    mov r0, str_nosale
    syscall SC_IPC_SENDMSG

    pop lr
    ret

action_winner:
    push lr

    sub sp, 0x80
    mov r1, r0
    mov r0, sp
    mov r2, 0x100
    call memcpy

    add sp, 0x80

    pop lr
    ret

action_uptime:
    push lr

    sub sp, 0x80
    mov r0, sp
    syscall SC_UPTIME

    mov r0, sp
    call strlen

    mov r1, r0
    mov r0, sp
    syscall SC_IPC_SENDMSG

    add sp, 0x80

    pop lr
    ret

main:
    mov r0, 0x1000
    sub sp, r0

ipcloop:
    call1 puts str_waiting

    ; zero out the stack
    mov r0, sp
    mov r1, 0x00
    mov r2, 0x100
    call memset

    ; recv message
    mov r0, sp
    mov r1, 0x100
    syscall SC_IPC_RECVMSG

    ; preserve recv len
    mov r4, r0

    ; print out message
    call1 puts str_got
    call2 puts_hex sp, r4
    call1 puts str_newline

    ; send message back
    ldrw r0, sp
    mov32 r1 0xf01dc0de
    cmp r0, r1
    bne message_not_fortune_cookie

    call action_fortune_cookie
    b message_next

message_not_fortune_cookie:
    mov32 r1, 0xbadf0001
    cmp r0, r1
    bne message_not_friendship

    call action_friendship
    b message_next

message_not_friendship:
    mov32 r1, 0xc0cac01a
    cmp r0, r1
    bne message_not_winner
    mov r0, sp
    call action_winner
    b message_next    

message_not_winner:
    mov32 r1, 0xc01db007
    cmp r0, r1
    bne message_next
    call action_uptime

message_next:
    b ipcloop

str_waiting:
.stringz "[+] waiting for data..\n"

str_got:
.stringz "GOT: "

str_newline:
.stringz "\n"

str_nosale:
.stringz "Friendship is not for sale, dummy!\n"


fortune0:
.stringz "This Isn't Pizza, This Is a Mistake! This is an Italian tragedy.\n"
fortune1:
.stringz "My gran could do better! And she's dead!\n"
fortune2:
.stringz "This lamb is so undercooked, it's following Mary to school!\n"
fortune3:
.stringz "There's enough garlic in here to kill every vampire in Europe.\n"
fortune4:
.stringz "Don't just stand there like a big f*ckin' muffin!\n"
fortune5:
.stringz "You put so much ginger in this, it's a Weasley.\n"
fortune6:
.stringz "I wouldn't trust you running a bath let alone a restaurant.\n"
fortune7:
.stringz "This fish is so raw, he's still finding Nemo.\n"

cookies:
.dd fortune0
.dd fortune1
.dd fortune2
.dd fortune3
.dd fortune4
.dd fortune5
.dd fortune6
.dd fortune7