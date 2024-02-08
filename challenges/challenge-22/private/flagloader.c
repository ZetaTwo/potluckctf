/*
 * Stage-0 "bootloader".
 * All this needs to do is flash the real bootloader, place the flag,
 * and reset.
 */

#include <unistd.h>
#include "nvmc.h"
#include "ficr.h"
#include "reset.h"
#include "uart.h"

#define FLASH_SIZE 0x40000

typedef void (*ptr_func_t)();

__attribute__((section(".start")))
void __stop() { while (1); }

void reset_handler();

__attribute__((section(".vectors"), used)) ptr_func_t __isr_vectors[] = {
    reset_handler, __stop, __stop, __stop,
    __stop, __stop, __stop, __stop,
    __stop, __stop, __stop, __stop,
    __stop, __stop, __stop, __stop,
    __stop, __stop, __stop, __stop,
    __stop, __stop, __stop, __stop,
    __stop, __stop, __stop, __stop,
    __stop, __stop, __stop, __stop,
};

extern u_int8_t __text_start;
extern u_int8_t __text_end;
extern u_int8_t __text_load;

extern u_int8_t __data_start;
extern u_int8_t __data_end;
extern u_int8_t __data_load;

extern u_int8_t __bss_start;
extern u_int8_t __bss_end;

void main();

__attribute__((section(".start")))
static inline
void _memcpy(void* dest, void* src, size_t len) {
    for(size_t i = 0; i < len; i++) {
        ((char*) dest)[i] = ((char*) src)[i];
    }
}

__attribute__((section(".start")))
static inline
void _memset(void* dest, char value, size_t len) {
    for(size_t i = 0; i < len; i++) {
        ((char*) dest)[i] = value;
    }
}

__attribute__((section(".start")))
void reset_handler() {
    _memcpy(&__text_start, &__text_load, (&__text_end - &__text_start));
    _memcpy(&__data_start, &__data_load, (&__data_end - &__data_start));
    _memset(&__bss_start, 0, &__bss_end - &__bss_start);
    main();
}

static size_t align_up(size_t value, size_t align) {
    if (value % align == 0) {
        return value;
    }

    return ((value / align) + 1) * align;
}

extern char _binary_bootloader_bin_end;
extern char _binary_bootloader_bin_start;

#ifndef FLAG2
#define FLAG2 potluck{second_flag_here}
#endif
#define _STR(s) #s
#define STR(s) _STR(s)
char flag[]=STR(FLAG2);
_Static_assert((sizeof(flag) <= 32), "Flag too long");
#define UICR_CUSTOMER ((void*) 0x10001080)
void main() {
    size_t pagesz = FICR->CODEPAGESIZE;
    size_t bootloader_size = &_binary_bootloader_bin_end - &_binary_bootloader_bin_start;
    size_t bootloader_size_aligned = align_up(bootloader_size, pagesz);
    nvmc_erase_uicr();
    nvmc_write(UICR_CUSTOMER, flag, sizeof(flag));
    for (void* page = 0; (size_t) page < bootloader_size_aligned; page += pagesz) {
        nvmc_erase_page(page);
        nvmc_write(page, &_binary_bootloader_bin_start + (size_t) page, pagesz);
        nvmc_erase_page(&_binary_bootloader_bin_start + (size_t) page);
    }
    for (size_t page = _binary_bootloader_bin_start + bootloader_size_aligned; page < FLASH_SIZE; page += pagesz) {
        nvmc_erase_page(&_binary_bootloader_bin_start + page);
    }
    // QEMU will not persist NVMC across resets, so we have to "fake" a reset here.
    // We set the initial stack pointer, and branch to the reset vector.
    asm volatile(
        "mov r0, #0\n"
        "ldr r1, [r0, #0]\n"
        "mov sp, r1\n"
        "ldr r0, [r0, #4]\n"
        "bx r0\n"
    );
    while (1) {}
}
