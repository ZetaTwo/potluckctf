MEMORY {
    FLASH(rx) : ORIGIN = 0x3000, LENGTH = 64K - 0x3000
    SRAM_RESERVED(rwx) : ORIGIN = 0x20000000, LENGTH = 0x100
    SRAM(rwx) : ORIGIN = 0x20000100, LENGTH = 16K - 0x100
}

SECTIONS {
    . = ORIGIN(FLASH);
    .text : {
        __text_start = .;
        KEEP(*(.stack))
        KEEP(*(.vectors))
        KEEP(*(.vectors*))
        KEEP(*(.text))
        . = ALIGN(4);
        *(.text*)
        . = ALIGN(4);
        KEEP(*(.rodata))
        *(.rodata*)
        . = ALIGN(4);
        __text_end = .;
    } >FLASH

    __bootloader_data_load = LOADADDR(.bootloader_data);
    . = ORIGIN(SRAM_RESERVED);

    .bootloader_data ALIGN(4) : {
        __bootloader_data_start = .;
        *(.bootloader_data)
        *(.bootloader_data*)
        . = ALIGN(4);
        __bootloader_data_end = .;
    } >SRAM_RESERVED AT >FLASH


    __stacktop = ORIGIN(SRAM) + LENGTH(SRAM);
    __data_load = LOADADDR(.data);
    . = ORIGIN(SRAM);

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


    /DISCARD/ :
    {
        *(.ARM.exidx)
        *(.ARM.exidx.*)
    }

    . = ALIGN(4);
    __heap_start = .;
}
