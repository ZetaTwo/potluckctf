#ifndef __NVIC_H__
#define __NVIC_H__
#include <unistd.h>

void nvic_enable_irq(int irq);
void nvic_disable_irq(int irq);
void nvic_set_pending(int irq);
void nvic_clear_pending(int irq);
void nvic_set_priority(int irq, char priority);
#endif