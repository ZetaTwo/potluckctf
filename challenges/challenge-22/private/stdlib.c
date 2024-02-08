#include <string.h>
#include "uart.h"
#include "ranges.h"

void copy_data() {
    memcpy(&__data_start, &__data_load, (&__data_end - &__data_start));
}

void zero_bss() {
    memset(&__bss_start, 0, &__bss_end - &__bss_start);
}

void fill_heap() {
    unsigned *dst = (unsigned *) &__heap_start;
    unsigned *msp_reg;
    __asm__("mrs %0, msp\n" : "=r" (msp_reg) );
    while (dst < msp_reg) {
        *dst++ = 0x45455246;
    }
}

void _putchar(char character) {
    uart_putc(character);
}

extern void main();

// reset handler
void RESET_handler() {
    copy_data();
    zero_bss();
    fill_heap();
    // run application
    main();
    // stop
    while (1);
}
