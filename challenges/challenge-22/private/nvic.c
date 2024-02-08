#include <unistd.h>

void nvic_enable_irq(int irq) {
    uint32_t * const ISER = (uint32_t*) 0xE000E100;
    *ISER |= 1 << irq;
}

void nvic_disable_irq(int irq) {
    uint32_t * const ICER = (uint32_t*) 0xE000E180;
    *ICER |= 1 << irq;
}

void nvic_set_pending(int irq) {
    uint32_t * const ISPR = (uint32_t*) 0xE000E200;
    *ISPR |= 1 << irq;
}

void nvic_clear_pending(int irq) {
    uint32_t * const ICPR = (uint32_t*) 0xE000E280;
    *ICPR |= 1 << irq;
}

/*
 * Each priority field holds a priority value, 0-192. The lower the value,
 * the greater the priority of the corresponding interrupt. The processor
 * implements only bits[7:6] of each field, bits [5:0] read as zero and
 * ignore writes. This means writing 255 to a priority register saves
 * value 192 to the register.
 */
void nvic_set_priority(int irq, char priority) {
    char * const IPR = (char*) 0xE000E400;
    IPR[irq] = priority;
}