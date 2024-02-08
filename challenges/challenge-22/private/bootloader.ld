INCLUDE nrf51.ld

SECTIONS {
    . = ORIGIN(FLASH);
    .text : {
        __text_start = .;
        KEEP(*(.stack))
        KEEP(*(.bootloader_vectors))
        KEEP(*(.bootloader_vectors*))
        KEEP(*(.text))
        . = ALIGN(4);
        *(.text*)
        . = ALIGN(4);
        KEEP(*(.vectors))
        KEEP(*(.vectors*))
        KEEP(*(.rodata))
        *(.rodata*)
        . = ALIGN(4);
        __text_end = .;
    } >FLASH

    /DISCARD/ :
    {
        *(.ARM.exidx)
        *(.ARM.exidx.*)
    }

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

    . = ALIGN(4);
    __heap_start = .;
}
