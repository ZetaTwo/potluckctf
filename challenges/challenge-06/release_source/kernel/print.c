#include <stdint.h>
#include "kernel.h"
#include "helper.h"



extern void INTWRAPPER();

char ps2Scancodes[] = {
        0, 0, '1', '2', '3', '4', '5', '6', '7', '8', '9', '0', '_', '=', '\r', '\t', 'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', '{', '}',
        '\n', 0, 'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l', ';', '\'', '`', 0, '\\', 'z', 'x', 'c', 'v', 'b', 'n', 'm', ',', '.', '/', 0, '*', 0, ' '
};

int last_pressed_key;
    
// Handle Interrupt
void INT_HANDLER() {
  int v = inb(0x60);
  
  if((v&0x80) == 0 && v < sizeof(ps2Scancodes) && ps2Scancodes[v] != 0) {
    last_pressed_key = ps2Scancodes[v];
  }

  outb(0xA0, 0x20);
  outb(0x20, 0x20); //EOI
                
}

char waitForKey() {
    last_pressed_key = 0;
    uint16_t oldKeyHandler = *((uint16_t*)(0x2000+8*(0x21)));
    // Install Key Handler
    disableInterrupts();
    *((uint16_t*)(0x2000+8*(0x21))) = (uint16_t)((int32_t)(&INTWRAPPER));
    enableInterrupts();

    // Receive Input
    while(!last_pressed_key) {
        wait();
    }
    
    // Remove Key Handler
    disableInterrupts();
    *((uint16_t*)(0x2000+8*(0x21))) = oldKeyHandler;
    enableInterrupts();
    
    return last_pressed_key;
}

// Print a character through serial
void putchar_serial(uint8_t c) {
    while(!(inb( 0x3f8 + 5) & 0x20));
    outb(0x3f8+0, c);
}

// Print a string until a null byte occurs
void puts_serial(char* str) {
    while(*str) putchar_serial(*(str++));
}


volatile uint16_t* SCREEN = (volatile uint16_t*)0xb8000; //  Text screen video memory for color monitors 
uint32_t screenIndex = 0; // cursor
// Print a character to the screen
void putchar(uint8_t c) {
    if(c == '\r') return;// ignore
    
    // if this would write outside of the screen scroll and reposition cursor
    if(screenIndex >= 80*25) {
        for(uint32_t i=0;i < 80*24;i++) // copy first 24 lines one line up
            SCREEN[i] = SCREEN[80+i];
        for(uint32_t i=0;i < 80;i++) // clear the 25th line
            SCREEN[80*24+i] = 0x0700;
        screenIndex = 80*24; // set the index to the start of the line
    }
        
    // newline repositions cursor to the start of the next line
    if(c == '\n') {
        uint32_t i = 80-(screenIndex%80); // this resets to the next line for 80x25 mode
        while(i--) SCREEN[screenIndex++] = 0x0700; // and clears the rest of the line
    }else
        SCREEN[screenIndex++] = (0x0700 | c); //0x07        ; The color: gray(7) on black(0)
}

// Print a string until a null byte occurs
void puts(char* str) {
    while(*str) putchar(*(str++));
}

// Print a newline
void printNewline() {
   putchar('\n');
}

char toDigit(uint8_t hex) {
    hex = hex&0xF;
    if(hex > 9) return ('a'+(hex-10));
    else        return('0'+(hex));
}

// Print a digit in hex format
void printDigit(uint8_t hex) {
    putchar(toDigit(hex));
}

// Print a 8bit value in hex format
void printHex(uint8_t hex) {
    printDigit(hex>>4);
    printDigit(hex);
}


// Print a 32bit address
void printAddr(uint32_t hex) {
    printHex(hex>>24);
    printHex(hex>>16);
    printHex(hex>>8);
    printHex(hex);
}

// Print Error Message Context and Halt
void exit(char* msg, int code) {
   printNewline();
   for(int i = 0; i < 30; i++)
       putchar('=');
   printNewline();
   puts("Failed ");
   if(msg) {
       putchar('\'');
       puts(msg);
       putchar('\'');
   }
   printNewline();
   puts("CODE ");
   printHex(code);
   printNewline();
   for(int i = 0; i < 30; i++) 
       putchar('=');
   printNewline();
   while(1); // freeze
}

