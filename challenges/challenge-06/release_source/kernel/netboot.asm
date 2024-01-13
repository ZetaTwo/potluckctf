; Expect this file to be more or less potato code that I wrote quite a while ago (and not really fully understand anymore)
; It works in qemu and to some degree on real hardware
; I had some problems with some technicalities on some test devices though

org 0x7C00
bits 16

; es:bx should point to the PXENV+ structure
; ss:sp should already point to a valid stack
; ss:sp + 4 should point to the !PXE structure (if PXE Version >= 1.5)


jmp short start
nop
nop
dd call_16 ; this calls PXE API with (SEGOFF16 PXEAPIEntryPont, SEGOFF16 DataPointer, uint32_t OpCode)
; Syscall table here for no real good reason
resd 16
start: 



; ------------------------------------------------------------------

; Initialize registers with zeros
cli
xor ax, ax
mov ds, ax
mov ss, ax
mov es, ax
mov fs, ax
mov gs, ax
mov sp, 0x7C00 ; setup the stack like qemu does
sti


; PXE Installation Check
;
; AX := 564Eh (VN)
; ES := 16-bit segment address of the PXENV+ structure.
; BX := 16-bit offset of the PXENV+.
; EDX := may be trashed by the UNDI INT 1Ah handler.
; All other register contents are preserved.
; CF is cleared.
; IF is preserved.
; All other flags are undefined.
;

mov ax, 0x5650
int 0x1A
; 0x5650 -> NO PXE
; 0x564E -> PXE

; Error if PXE is not installed
cmp ax, 0x564E
jne NO_PXE_INSTALLED

; Save PXENV+ Structure Position
mov word [cs:PXENVPtr], bx
mov word [cs:PXENVPtrES], es

jmp 0:enterProtectedMode

enterProtectedMode:

; Disable maskable interrupts
cli

; Disasble non maskable interrupts (NMI)
in al, 0x70 
or al, 0x80
out 0x70, al

; Load the GDT
lgdt [GTD_DESC]

; switch the Protected Mode Bit
mov eax, cr0
or al, 1
mov cr0, eax

; Initilize the segments with the data segment
mov ax, DATA_SEG
mov ds, ax
mov es, ax
mov fs, ax
mov gs, ax
mov ss, ax
mov esp, 0x7C00

; Jump to the code segment
jmp CODE_SEG:_entry

NO_PXE_INSTALLED:  
    mov si, noInstallPXE
PRINT_ERROR:
    mov bh, 0x00          ; page 0
    mov bl, 0x07          ; text attribute
    mov ah, 0x0E          ; tells BIOS to print char
    .part:
    lodsb                 ; load character to print
    sub al, 0
    jz end
    int 0x10              ; print character
    jmp .part
    end:
    jmp $

noInstallPXE     db "No PXE Installation Found...",0  
        
bits 32
_entry:

; Optional Code to be able to process interrupts again
; Initialize Interrupt Description Table IDT with dummy entries
mov ecx, 256
xor edi, edi ; write the IDT starting at address 0x2000
mov edi, 0x2000
.loop:
    mov word  [edi],   idt_dummy ; first 16 bit offset
    mov word  [edi+2], CODE_SEG  ; code segment selector in GDT
    mov byte  [edi+4], 0x0       ; unused, set to 0
    mov byte  [edi+5], 0x8E      ; type and attributes (Present bit, 32bit Interrupt Gate)
    mov word  [edi+6], 0         ; last 16 bit offset
    add edi, 8
    dec ecx
    jnz .loop
    
; Move IRQs
; See https://wiki.osdev.org/8259_PIC - PIC_remap
mov al, 0x11
out 0x20, al
mov al, 0
out 0x80, al
mov al, 0x11
out 0xA0, al
mov al, 0
out 0x80, al
mov al, 0x20
out 0x21, al
mov al, 0
out 0x80, al
mov al, 40
out 0xA1, al
mov al, 0
out 0x80, al
mov al, 0x04
out 0x21, al
mov al, 0
out 0x80, al
mov al, 0x02
out 0xA1, al
mov al, 0
out 0x80, al
mov al, 0x01
out 0x21, al
mov al, 0
out 0x80, al
mov al, 0x01
out 0xA1, al
mov al, 0
out 0x80, al
mov al, 0x00
out 0x21, al
mov al, 0
out 0x80, al
mov al, 0x00
out 0xA1, al
mov al, 0
out 0x80, al

; Disable all but keyboard
mov al, 0xff
out 0xa1, al
mov al, 0xfd
out 0x21, al

lidt [PM_IDT_ptr] ; Load Dummy IDT
sti               ; Enable interrupts again thanks to IDT

mov esp, 0x0007ffff ; more stack space...
push dword [PXENVPtr] ; Push pointer to pxenv+
jmp KERNEL_CODE

; Dummy Interrupt Handler
idt_dummy:

    pushad
    in al, 0x60   ; read keyboard, might not retrigger if not read
    
    ; ack interrupt
    mov al, 0x20
    out 0xA0, al
    mov al, 0x20
    out 0x20, al
    popad
iret


PM_IDT_ptr:    dw 8*256-1 ; Length (256 Entires, each have a size of 8 bytes)
               dd 0x2000    ; Offset (Position of IDT which is at address 0x2000)

RM_IDT_ptr:    dw 0x03ff ; Length (128 Entries)
               dd 0      ; Offset (IVT is at 0x0000)



bits 16
; This calling convention works for both !PXE -> EntryPointSP and PXEnv+ -> RMEntry
PXEAPI:
    mov word [es:di],0       ; reset status code before calling the api
    push es                  ; push segment of structure
    push di                  ; push address of structure
    push bx                  ; push the PXE API Opcode
    call far [cs:PXE_API]    ; call the PXE API
    add sp,6                 ; cleanup the stack
    mov ax, [es:di]          ; read the error code and return it
    ret

; This does not solve possible IDT problems
; See https://github.com/joyent/syslinux/blob/b78ed9f973e228e886229ccd9ab41dc228cb81b6/core/pm.inc
; for how syslinux solves this
Entry16:    
    mov ax, DATA_SEG16 ; 16-bit Protected Mode data selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    lidt [RM_IDT_ptr] ; load the realmode IVT
   
    mov eax, cr0
    and eax, 0x7FFFFFFE    ; Disable paging bit & disable 16-bit pmode.
    mov cr0, eax
    
    jmp 0:.GoRealMode  ; make sure cs = 0
.GoRealMode:
    ; Pick a stack pointer for the real mode code execution.
    ; MUST NOT COLLIDE WITH PROTECTED MODE STACK POINTER.
    mov sp, 0x5000
    
    mov ax, 0                     ; Reset segment registers to 0
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    
    ; load the parameters
    mov di, word [cs:DataPosition]
    mov es, word [cs:DataPosition+2]
    mov bx, word [cs:OpCode]
    call PXEAPI ; call realmode PXEAPI
    
    cli
    cld
    
    mov word [cs:RetVal], ax ; save the return value
    
    lgdt [cs:GTD_DESC]   ; load the descriptor table again
    lidt [cs:PM_IDT_ptr] ; load the protected mode interrupt description table again
    
    mov eax, cr0
    or al, 1         ; switch the Protected Mode Bit
    mov cr0, eax

    mov ax, DATA_SEG ; 32-bit Protected Mode data selector
    mov ds, ax
    mov es, ax
    mov fs, ax
    mov gs, ax
    mov ss, ax
    ; jump to the code segment
    jmp CODE_SEG:call_16.reenter ; ; 32-bit Protected Mode code selector  
    
bits 32
call_16:
    cli ; disable interrupts
    cld ; clear the direction fkla
    mov eax, dword [esp+4]
    mov dword [PXE_API], eax ; copy over SEGOFF16 PXE API Entrypoint (!PXE -> EntryPointSP or PXEnv+ -> RMEntry)
    mov eax, dword [esp+8]
    mov dword [DataPosition], eax ; copy over SEGOFF16 call data parameter (MUST BE IN 16bit Addressable Range)
    mov eax, dword [esp+12]
    mov dword [OpCode], eax ; copy over the PXE API Opcode (See Specifications)
    pushfd ; push 32 bit eflags
    pushad ; save all 32 bit registers
    mov dword [saveESP], esp ; save the protected mode stack pointer
    jmp CODE_SEG16:Entry16 ; jump to further code with the 16-bit Protected Mode code selector
    .reenter: ; after getting back to protected mode code reenters here
    mov esp, dword [saveESP] ; load the protected mode stack pointer
    popad ; pop all 32 bit registers
    popfd ; pop 32 bit eflags
    mov eax, dword [RetVal] ; load the PXEAPI return value
    sti ; re-enable interrupts
    ret
    
; call_16 associated variables
saveESP dd 0
PXE_API dd 0
DataPosition dd 0
OpCode dd 0
RetVal dd 0

; PXENV+ Structure
PXENVPtr dw 0
PXENVPtrES dw 0


; Example Global Descriptor Table with Flat Memory Layout for Protected Mode Kernel, Protected Mode Userland and Realmode Kernel segments
CODE_SEG equ GDT_CODE - GDT_TABLE
DATA_SEG equ GDT_DATA - GDT_TABLE

CODE_SEG16 equ GDT_CODE16 - GDT_TABLE
DATA_SEG16 equ GDT_DATA16 - GDT_TABLE

GTD_DESC:
   dw GDT_TABLE_END - GDT_TABLE
   dd GDT_TABLE

GDT_TABLE: ; 0
        dw 0x0 ; limit_low
        dw 0x0 ; base_low
        db 0x0 ; base_middle
        db 0x0 ; access
        db 0x0 ; granularity
        db 0x0 ; base_high
; kernel code segment
GDT_CODE: ; 8
        dw 0xffff ; limit_low
        dw 0x0 ; base_low
        db 0x0 ; base_middle
        db 0x9a ; access
        db 0xcf ; granularity
        db 0x0 ; base_high
GDT_DATA: ; 16
; kernel data segment
        dw 0xffff ; limit_low
        dw 0x0 ; base_low
        db 0x0 ; base_middle
        db 0x92 ; access
        db 0xcf ; granularity
        db 0x0 ; base_high
GDT_CODE16: ; 24
        dw 0xffff ; limit_low
        dw 0x0 ; base_low
        db 0x0 ; base_middle
        db 0x9a ; access
        db 0xf ; granularity
        db 0x0 ; base_high
; 16 bit kernel data segment
GDT_DATA16: ; 32
        dw 0xffff ; limit_low
        dw 0x0 ; base_low
        db 0x0 ; base_middle
        db 0x92 ; access
        db 0xf ; granularity
        db 0x0 ; base_high
GDT_TABLE_END:


times 1024-($-$$) db 0x90 ; some alignment, not really necessary
KERNEL_CODE: ; protected mode "kernel" code will be copied here