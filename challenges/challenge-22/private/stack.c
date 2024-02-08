
extern unsigned __stacktop;

__attribute__((section(".stack"), used)) unsigned *__stack_init = &__stacktop;