#include <stdint.h>
#include "kernel.h"
#include "helper.h"

// See https://wiki.osdev.org/A20_Line

// Check if the A20 Line is activated by writing and reading from memory that would be the same if it is not
uint8_t checkA20() { 
    *((volatile uint32_t*)0x012345) = 0x012345;
    *((volatile uint32_t*)0x112345) = 0x112345;
    return *((volatile uint32_t*)0x012345) !=  *((volatile uint32_t*)0x112345);
}

// Initialize the A20 line through the keyboard controller
void initA20() {
   
   disableInterrupts();
   
    while (inb(0x64) & 0x02); // is input buffer of keyboard status full
    while (inb(0x64) & 0x01)  // is output buffer of keyboard status full
    (void)inb(0x60);          // read keyboard data & cmds
    outb(0x64, 0xd1);         // write output port to keyboard control command
    while (inb(0x64) & 0x02); // is input buffer of keyboard status full
    outb(0x60, 0x9f);         // write enable A20 command to keyboard commands
    while (inb(0x64) & 0x02); // is input buffer of keyboard status full
    
   enableInterrupts();
}

// Try to activate the A20 line or loop forever if unsuccessful
void activateA20() {
    if(checkA20()) return;
    initA20();
    if(checkA20()) return;
    puts("A20 Line could not be activated.\n");
    while(1) {
        wait();
    }
}