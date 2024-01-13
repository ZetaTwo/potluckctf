bits 32

global _start
global PXEAPI
global INTWRAPPER

extern entrypoint
extern INT_HANDLER


section .text

; entrypoint of the linked file
_start:
    call entrypoint
    add esp, 4

    ; hlt loop after execution
    done:
        hlt
        jmp done


; invoke PXEAPI through going back to Real Mode
PXEAPI:
    jmp dword [0x7C04]


; wrapper for interrupts
INTWRAPPER:
    pushfd
    pushad
    call INT_HANDLER
    popad
    popfd
    iret