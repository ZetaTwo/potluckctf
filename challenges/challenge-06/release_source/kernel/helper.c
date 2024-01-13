#include "helper.h"

// Trivial strcpy implementation
void strcpy(volatile char* dest, char* src) {
    while(*src) {
        *(dest++) = *(src++);
    }
    *dest = 0;
}


void * memcpy(void *dst, const void *src, size_t length) {
    if ((unsigned long)dst < (unsigned long)src) {
        for(size_t i=0;i<length;i++) {
            ((char*)dst)[i] = ((char*)src)[i];
        }
    }else {
        for(size_t i=length;i>0;i--) {
            ((char*)dst)[i-1] = ((char*)src)[i-1];
        }
    }
    return dst;
}

void * memmove(void *dst, const void *src, size_t length) {
    return memcpy(dst, src, length);
}

size_t strlen(const char *str) {
    const char* s = str;
    for (; *s != 0; s++);
    return(s - str);
}


int memcmp(const void* s1, const void* s2, size_t n) {
    unsigned char u1, u2;
    for ( ; n-- ; s1++, s2++) {
        u1 = * (unsigned char *)s1;
        u2 = * (unsigned char *)s2;
        if (u1 != u2) {
            return (u1-u2);
        }
    }
    return 0;
}

void * memset (void *dest, int val, size_t len) {
  unsigned char *ptr = (unsigned char*)dest;
  while (len > 0) {
    *ptr++ = val;
    len--;
  }
  return dest;
}



/*
 * https://github.com/glitchub/arith64
 * Public Domain
*/
#include "arith64.c"

/*
 * Copyright (c) 2013, NLnet Labs. All rights reserved.
 * Open Source
*/
#include "snprintf.c"