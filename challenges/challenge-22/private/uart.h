#ifndef __UART_H__
#define __UART_H__
#include <unistd.h>

void uart_init();
void uart_putc(char c);
void uart_puts(char* s);
char uart_getc();
void uart_gets(char *dest, size_t n);
void uart_read(char *const dest, size_t n);
void uart_write(char *const src, size_t n);
#endif
