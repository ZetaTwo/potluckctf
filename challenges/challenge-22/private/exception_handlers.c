#include <unistd.h>
#include <string.h>
#include "ranges.h"
#include "exception_handlers.h"


void __stop() { while (1); }

__attribute__((weak, alias("__stop")))
void __default_irq_handler();

__attribute__((weak, alias("__stop")))
void __default_reset_handler();

__attribute__((weak, alias("__default_reset_handler"))) void RESET_handler();
__attribute__((weak, alias("__default_irq_handler"))) void NMI_handler();
__attribute__((weak, alias("__default_irq_handler"))) void HARDFAULT_handler();
__attribute__((weak, alias("__default_irq_handler"))) void MEMMANAGE_handler();
__attribute__((weak, alias("__default_irq_handler"))) void BUSFAULT_handler();
__attribute__((weak, alias("__default_irq_handler"))) void USAGEFAULT_handler();
__attribute__((weak, alias("__default_irq_handler"))) void SVCALL_handler();
__attribute__((weak, alias("__default_irq_handler"))) void DEBUGMONITOR_handler();
__attribute__((weak, alias("__default_irq_handler"))) void PENDSV_handler();
__attribute__((weak, alias("__default_irq_handler"))) void SYSTICK_handler();
__attribute__((weak, alias("__default_irq_handler"))) void DUMMY_handler();
__attribute__((weak, alias("__default_irq_handler"))) void UARTE0_UART0_IRQHandler();

__attribute__((section(".vectors"), used)) const ptr_func_t __bootloader_isr_vectors[] = {
    RESET_handler,
    NMI_handler,
    HARDFAULT_handler,
    MEMMANAGE_handler,
    BUSFAULT_handler,
    USAGEFAULT_handler,
    DUMMY_handler,
    DUMMY_handler,
    DUMMY_handler,
    DUMMY_handler,
    SVCALL_handler,
    DEBUGMONITOR_handler,
    DUMMY_handler,
    PENDSV_handler,
    SYSTICK_handler,
    DUMMY_handler, // external interrupt 0
    DUMMY_handler, // external interrupt 1
    UARTE0_UART0_IRQHandler, // external interrupt 2
    DUMMY_handler, // external interrupt 3
    DUMMY_handler, // external interrupt 4
    DUMMY_handler, // external interrupt 5
    DUMMY_handler, // external interrupt 6
    DUMMY_handler, // external interrupt 7
    DUMMY_handler, // external interrupt 8
    DUMMY_handler, // external interrupt 9
    DUMMY_handler, // external interrupt 10
    DUMMY_handler, // external interrupt 11
    DUMMY_handler, // external interrupt 12
    DUMMY_handler, // external interrupt 13
    DUMMY_handler, // external interrupt 14
    DUMMY_handler, // external interrupt 15
};
