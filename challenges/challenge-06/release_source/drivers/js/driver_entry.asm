bits 32

global _start
extern entrypoint

section .text

; entrypoint of the linked file
_start:
    call entrypoint
    ret
