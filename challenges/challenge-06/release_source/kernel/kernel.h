#ifndef KERNEL_H
#define KERNEL_H

#include "pxe.h"

// Enable A20 Line Functions (a20.c)
uint8_t checkA20();
void initA20();
void activateA20();

// Print Routines (print.c)
void putchar_serial(uint8_t c);
void puts_serial(char* str);

void putchar(uint8_t c);
void puts(char* str);

char waitForKey();

// debugg-y stuff
void printNewline();
void printHex(uint8_t hex);
void printAddr(uint32_t hex);
void exit(char* msg, int code);

// PXE Stuff
void initPXE(SEGOFF16 pxe);
uint32_t readFile(char* filePath, uint8_t* dest, uint32_t maxSize);


void strcpy(volatile char* dest, char* src);

#endif