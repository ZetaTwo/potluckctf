#ifndef HELPER_H
#define HELPER_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

// Wrapper around x86 instructions

static inline void outb(uint16_t port, uint8_t val) {
    asm volatile ( "outb %0, %1" : : "a"(val), "Nd"(port) );
}


static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile ( "inb %1, %0"
                   : "=a"(ret)
                   : "Nd"(port) );
    return ret;
}


static inline void disableInterrupts() {
    asm volatile ( "cli" );
}

static inline void enableInterrupts() {
    asm volatile ( "sti");
}

static inline void wait() {
    asm volatile ( "hlt");
}

void strcpy(volatile char* dest, char* src);
size_t strlen(const char *str);
void * memcpy(void *dst, const void *src, size_t length);
void * memmove(void *dst, const void *src, size_t length);
int memcmp(const void* s1, const void* s2, size_t n);
void * memset (void *dest, int val, size_t len);
int snprintf(char* str, size_t size, const char* format, ...);
int vsnprintf(char* str, size_t size, const char* format, va_list arg);

#endif