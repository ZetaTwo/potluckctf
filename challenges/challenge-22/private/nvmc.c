#include <unistd.h>
#include "ficr.h"
#include "printf/printf.h"

#define NRF51_NVMC_BASE       0x4001E000

#define MIN(a, b) (a > b ? b : a)

__attribute__((packed))
struct NVMC {
    char __padding0[0x400];
    uint32_t READY;     // 0x400 Ready flag
    char __padding1[0x100];
    uint32_t CONFIG;    // 0x504 Configuration register
    uint32_t ERASEPAGE; // 0x508 Register for erasing a page in Code area
    uint32_t ERASEALL;  // 0x50C Register for erasing all non-volatile user memory
    uint32_t ERASEPCR0; // 0x510 Register for erasing a page in Code area. Equivalent to ERASEPAGE. Deprecated.
    uint32_t ERASEUICR; // 0x514 Register for erasing User Information Configuration Registers
    char __padding2[0x28];
    uint32_t ICACHECNF; // 0x540 I-Code cache configuration register.
    uint32_t __padding3;
    uint32_t IHIT;      // 0x548 I-Code cache hit counter.
    uint32_t IMISS;     // 0x54C I-Code cache miss counter.
};

_Static_assert((__offsetof(struct NVMC, IMISS) == 0x54C), "struct NVMC borked");

static struct NVMC *const NVMC = (struct NVMC*) 0x4001E000;

static inline
void nvmc_wait_for_ready() {
    while (NVMC->READY != 1) {};
}

static inline
void nvmc_enable_write() {
    NVMC->CONFIG = 1;
}

static inline
void nvmc_enable_erase() {
    NVMC->CONFIG = 2;
}

static inline
void nvmc_disable_write() {
    NVMC->CONFIG = 0;
}

static inline
void* align_page(void* addr) {
    return (void*) ((size_t) addr & ~(FICR->CODEPAGESIZE - 1));
}

void nvmc_erase_all() {
    nvmc_enable_erase();
    NVMC->ERASEALL = 1;
    nvmc_wait_for_ready();
    nvmc_disable_write();
}

void nvmc_erase_page(void* addr) {
    nvmc_enable_erase();
    NVMC->ERASEPAGE = (uint32_t) align_page(addr);
    nvmc_wait_for_ready();
    nvmc_disable_write();
}

void nvmc_erase_uicr() {
    nvmc_enable_erase();
    NVMC->ERASEUICR = 1;
    nvmc_wait_for_ready();
    nvmc_disable_write();
}


static inline uint32_t unaligned_read(void* addr) {
    if ((size_t) addr % 4 == 0) {
        return *((uint32_t*) addr);
    }

    return ((char*) addr)[3] << 24
      | ((char*) addr)[2] << 16
      | ((char*) addr)[1] << 8
      | ((char*) addr)[0];
}

void nvmc_write(void* dest, void* src, size_t length) {
    if (length == 0)
        return;
    uint32_t end_mask = 0;
    size_t start_offset = ((size_t) dest) % 4;
    uint32_t word = (*((uint32_t *) src));
    switch (start_offset) {
        case 1:
            word = 0xFF | ((word & 0xFFFFFF) << 8);
            break;
        case 2:
            word = 0xFFFF | ((word & 0xFFFF) << 16);
            break;
        case 3:
            word = 0xFFFFFF | ((word & 0xFF) << 24);
            break;
    }

    dest -= start_offset;
    src -= start_offset;
    length += start_offset;

    nvmc_enable_write();
    while (length) {
        end_mask = 0;
        if (length < 4) {
            end_mask = - (1 << (8*length));
        }
        *((uint32_t*) dest) = word | end_mask;
        nvmc_wait_for_ready();
        dest += 4;
        src += 4;
        word = unaligned_read(src);
        length -= MIN(length, 4);
    }
    nvmc_disable_write();
}