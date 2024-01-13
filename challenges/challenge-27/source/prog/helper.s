.macro syscall1
    mov r0, $2
    syscall $1
.endmacro

.macro syscall2
    mov r0, $2
    mov r1, $3
    syscall $1
.endmacro

.macro syscall3
    mov r0, $2
    mov r1, $3
    mov r2, $4
    syscall $1
.endmacro

.macro call1
    mov r0, $2
    call $1
.endmacro

.macro call2
    mov r0, $2
    mov r1, $3
    call $1
.endmacro

.macro call3
    mov r0, $2
    mov r1, $3
    mov r2, $4
    call $1
.endmacro

.macro push2
    push $1
    push $2
.endmacro

.macro push3
    push $1
    push $2
    push $3
.endmacro

.macro push4
    push $1
    push $2
    push $3
    push $4
.endmacro

.macro push6
    push $1
    push $2
    push $3
    push $4
    push $5
    push $6    
.endmacro

.macro pop2
    pop $2
    pop $1
.endmacro


.macro pop3
    pop $3
    pop $2
    pop $1
.endmacro


.macro pop4
    pop $4
    pop $3
    pop $2
    pop $1
.endmacro

.macro pop6
    pop $6
    pop $5    
    pop $4
    pop $3
    pop $2
    pop $1
.endmacro


.macro mov32
    mov $1, ($2>>16)
    shl $1, 8
    or $1, (($2>>8)&0xff)
    shl $1, 8
    or $1, ($2&0xff)
.endmacro