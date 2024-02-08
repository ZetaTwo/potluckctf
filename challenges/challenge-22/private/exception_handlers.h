#ifndef __EXCEPTION_HANDLERS_H__
#define __EXCEPTION_HANDLERS_H__

typedef void (*ptr_func_t)();

void RESET_handler();
void NMI_handler();
void HARDFAULT_handler();
void MEMMANAGE_handler();
void BUSFAULT_handler();
void USAGEFAULT_handler();
void SVCALL_handler();
void DEBUGMONITOR_handler();
void PENDSV_handler();
void SYSTICK_handler();
void DUMMY_handler();
void UARTE0_UART0_IRQHandler();
#endif
