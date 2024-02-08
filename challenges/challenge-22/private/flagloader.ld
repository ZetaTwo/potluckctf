MEMORY {
    FLASH(rx) : ORIGIN = 0, LENGTH = 64K
    SRAM(rwx) : ORIGIN = 0x20000000, LENGTH = 16K
}

SECTIONS {
    . = ORIGIN(FLASH);
    .start : {
        __start_start = .;
        KEEP(*(.stack))
        KEEP(*(.vectors))
        KEEP(*(.vectors*))
        KEEP(*(.start))
        . = ALIGN(4);
        *(.start*)
        . = ALIGN(4);
        KEEP(*(.rodata))
        *(.rodata*)
        . = ALIGN(0x400);
        *(.embed)
        *(.embed*)
        . = ALIGN(4);
        __start_end = .;
    } >FLASH

    __stacktop = ORIGIN(SRAM) + LENGTH(SRAM);
    __data_load = LOADADDR(.data);
    __text_load = LOADADDR(.text);
    . = ORIGIN(SRAM);

    .text ALIGN(4) : {
        __text_start = .;
        *(.text)
        *(.text*)
        . = ALIGN(4);
        __text_end = .;
    } >SRAM AT >FLASH

    .data ALIGN(4) : {
        __data_start = .;
        *(.data)
        *(.data*)
        . = ALIGN(4);
        __data_end = .;
    } >SRAM AT >FLASH

    .bss ALIGN(4) (NOLOAD) : {
        __bss_start = .;
        *(.bss)
        *(.bss*)
        . = ALIGN(4);
        __bss_end = .;
        *(.noinit)
        *(.noinit*)
    } >SRAM

    . = ALIGN(4);
    __heap_start = .;
}