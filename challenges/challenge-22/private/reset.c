#include <unistd.h>

void reset() {
    uint32_t *const AIRCR = (uint32_t *const) 0xE000ED0C;
    *AIRCR = 0x05FA0004;
}
