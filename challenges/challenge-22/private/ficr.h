#ifndef __FICR_H__
#define __FICR_H__
#include <unistd.h>

__attribute__((packed))
struct FICR {
    char __padding0[0x10];
    uint32_t CODEPAGESIZE;   // 0x010 Code memory page size
    uint32_t CODESIZE;       // 0x014 Code memory size
    char __padding1[0x48];
    uint32_t DEVICEID[2];    // 0x060 Device identifier
    char __padding2[0x18];
    uint32_t ER[4];          // 0x080 Encryption Root
    uint32_t IR[4];          // 0x090 Identity Root
    uint32_t DEVICEADDRTYPE; // 0x0a0 Device address type
    uint32_t DEVICEADDR[2];  // 0x0a4 Device address
    char __padding3[0x54];
    uint32_t INFO_PART;      // 0x100 Part code
    uint32_t INFO_VARIANT;   // 0x104 Part Variant, Hardware version and Production configuration
    uint32_t INFO_PACKAGE;   // 0x108 Package option
    uint32_t INFO_RAM;       // 0x10C RAM variant
    uint32_t INFO_FLASH;     // 0x110 Flash variant
};

_Static_assert((__offsetof(struct FICR, INFO_FLASH) == 0x110), "FICR Offsets borked.");

static struct FICR *const FICR = (struct FICR *const) 0x10000000;

#endif


