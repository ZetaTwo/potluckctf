#include "uart.h"
#include "printf/printf.h"
#include "ranges.h"
#include <string.h>
#include "sha256.h"
#include "reset.h"
#include "stdlib.h"
#include "nvmc.h"
#include "exception_handlers.h"

#ifndef FLAG1
#define FLAG1 potluck{first_flag_goes_here}
#endif
#define _STR(s) #s
#define STR(s) _STR(s)
__attribute__((used))
static const char flag[]=STR(FLAG1);

#define BOOTLOADER_RESET_MAGIC 0x600db007
#define FLASHSZ 64*1024

uint32_t flash_done = 0;
size_t app_start = 0;

struct bootloader_data {
    ptr_func_t const* interrupt_table_offset;
    void** initial_stack;
    uint32_t bootloader_inited;
};

extern const ptr_func_t __bootloader_isr_vectors[];

void bootloader_isr();
void bootloader_reset_handler();

__attribute__((section(".bootloader_vectors"), used)) ptr_func_t __isr_vectors[] = {
    bootloader_reset_handler, bootloader_isr, bootloader_isr, bootloader_isr,
    bootloader_isr, bootloader_isr, bootloader_isr, bootloader_isr,
    bootloader_isr, bootloader_isr, bootloader_isr, bootloader_isr,
    bootloader_isr, bootloader_isr, bootloader_isr, bootloader_isr,
    bootloader_isr, bootloader_isr, bootloader_isr, bootloader_isr,
    bootloader_isr, bootloader_isr, bootloader_isr, bootloader_isr,
    bootloader_isr, bootloader_isr, bootloader_isr, bootloader_isr,
    bootloader_isr, bootloader_isr, bootloader_isr, bootloader_isr,
};

__attribute__((section(".bootloader_data"), used))
static struct bootloader_data bootloader = {
    .interrupt_table_offset = __bootloader_isr_vectors,
    .initial_stack = NULL,
    .bootloader_inited = BOOTLOADER_RESET_MAGIC
};

// Cortex M0 doesn't have a VTOR, so we emulate it.
void bootloader_isr() {
    uint32_t *ICSR = (uint32_t*) 0xE000ED04;
    uint32_t vector = (*ICSR) & 0x3F;
    bootloader.interrupt_table_offset[vector - 1]();
}

void bootloader_reset_handler() {
    if (bootloader.bootloader_inited != BOOTLOADER_RESET_MAGIC)
        memcpy(&__bootloader_data_start, &__bootloader_data_load, (&__bootloader_data_end - &__bootloader_data_start));
    bootloader.interrupt_table_offset[0]();
}

void flash(char* command);
void checksum(char* command);
void checksum_usage();
void boot();

#define FLASH_COMMAND_SKIP 1
#define FLASH_COMMAND_DATA 2
#define FLASH_COMMAND_DONE 3
#define MAX_FLASH_CHUNKSZ 0x100-8

void print_digest(char digest[0x20]) {
    for (int i = 0; i < SHA256_BLOCK_SIZE; i ++) {
        printf("%02x", digest[i]);
    }
}

uint32_t flash_opcode(uint32_t opcode, size_t *cursor, SHA256_CTX *ctx) {
    size_t flashlen = 0;
    size_t skiplen = 0;
    char buf[MAX_FLASH_CHUNKSZ];

    switch (opcode) {
        case FLASH_COMMAND_SKIP:
            uart_read(&skiplen, sizeof(skiplen));
            *cursor += skiplen;
            break;
        case FLASH_COMMAND_DATA:
            uart_read(&flashlen, sizeof(flashlen));
            uart_read(&skiplen, sizeof(skiplen));
            if ((flashlen > MAX_FLASH_CHUNKSZ) || (*cursor < &__text_end) || (*cursor + flashlen > FLASHSZ) || (*cursor + flashlen < &__text_end)) {
                printf("ERR: Out of range: %p\n", *cursor);
                return 0;
            }
            if (app_start == 0) {
                app_start = *cursor;
            }
            uart_read(buf, flashlen);
            sha256_update(ctx, buf, flashlen);
            nvmc_write(*cursor, buf, flashlen);
            *cursor += flashlen;
            *cursor += skiplen;
            break;
        case FLASH_COMMAND_DONE:
            uart_puts("done.");
            return 1;
        default:
            uart_puts("ERR: Invalid Opcode.");
    }
    uart_puts("OK.");
    return 0;
}

extern char app_hash[];

uint8_t hashcmp(char* a, char*b) {
    uint8_t result = 0;

    for (int i = 0; i < SHA256_BLOCK_SIZE; i++) {
        result |= a[i] ^ b[i];
    }

    return result;
}

void flash(char* command) {
    uint8_t opcode;
    size_t cursor = 0;
    SHA256_CTX ctx;
    sha256_init(&ctx);
    flash_done = 0;
    app_start = 0;
    char digest[SHA256_BLOCK_SIZE];
    while(1) {
        printf("FLASH> ");
        uart_read(&opcode, sizeof(opcode));
        if (flash_opcode(opcode, &cursor, &ctx))
            break;
    }
    sha256_final(&ctx, &digest);

    if (hashcmp(digest, app_hash)) {
        printf("Checksum Failure! Can't flash third-party firmware!\n");
        printf("\n  expected: ");
        print_digest(app_hash);
        printf("\n  actual: ");
        print_digest(digest);
        printf("\n");
        return;
    }

    flash_done = 1;
    return;
}

void checksum(char* command) {
    char * name = strsep(&command, " ");
    char *s_start = strsep(&command, " ");

    if (s_start == NULL) {
        checksum_usage();
        return;
    }

    uint32_t start = strtoul(s_start, NULL, 16);

    char *s_length = strsep(&command, " ");
    if (s_length == NULL) {
        checksum_usage();
        return;
    }

    uint32_t length = strtoul(s_length, NULL, 16);

    if (length < 0x10) {
        printf("Length 0x%x too short!\n", length);
        return;
    }

    if (start + length < start) {
        printf("Length 0x%x too large!\n", length);
        return;
    }

    if ((start >= FLASHSZ) || (start + length >= FLASHSZ)) {
        printf("Can only checksum flash!\n");
        return;
    }

    char digest[SHA256_BLOCK_SIZE];

    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (char*) start, length);
    sha256_final(&ctx, (char*) &digest);

    printf("SHA256(0x%08x - 0x%08x): ", start, start + length);
    print_digest(digest);
    printf("\n");
}

void checksum_usage() {
    printf("Usage: checksum <start> <length>\n");
}

void boot() {
    if(flash_done == 0) {
        printf("Send flash first.\n");
        return;
    }

    bootloader.initial_stack = (void*) app_start;
    bootloader.interrupt_table_offset = (void*) app_start+4;

    asm volatile(
        "mov r0, %0\n"
        "mov sp, r0\n"
        "mov r0, %1\n"
        "bx r0\n"
        :: "r"(*bootloader.initial_stack), "r"(bootloader.interrupt_table_offset[0])
    );
}

void main() {
    uart_init();

    printf(".text 0x%08x - 0x%08x\n", &__text_start, &__text_end);
    printf(".bss  0x%08x - 0x%08x\n", &__bss_start, &__bss_end);
    printf(".data 0x%08x - 0x%08x (0x%08x)\n", &__data_start, &__data_end, &__data_load);
    printf("\n");
    char input[0x40];
    while (1) {
        printf("SEKURBUT> ");
        uart_gets(input, 0x40);
        if (strncmp(input, "flash", strlen("flash")) == 0) {
            flash(input);
            continue;
        }
        if (strncmp(input, "checksum", strlen("checksum")) == 0) {
            checksum(input);
            continue;
        }
        if (strcmp(input, "boot") == 0) {
            boot();
            continue;
        }
        if (strcmp(input, "reset") == 0) {
            reset();
            continue;
        }
        printf("commands:\n  flash    - flash firmware\n  checksum - checksum flash\n  boot     - boot firmware\n  reset    - reboot the machine\n");
    }
}
