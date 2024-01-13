#ifndef INTERFACE_H
#define INTERFACE_H

#include <stdint.h>

#define SYSCALL_TABLE   0x7C08

#define SYSCALL_PUTCHAR         0
#define SYSCALL_PUTS            1
#define SYSCALL_PUTCHAR_SERIAL  2
#define SYSCALL_PUTS_SERIAL     3
#define SYSCALL_WAIT_FOR_KEY    4
#define SYSCALL_READ_FILE       5
#define SYSCALL_SCREENINDEX_PTR 6
#define SYSCALL_EXECUTE_JS      7
#define SYSCALL_EXECUTE_VM      8



#define DRIVER_JS             0x00100000
#define DRIVER_JS_SIZE        0x00080000
#define DRIVER_JS_STRUCT      0x00180000
#define DRIVER_JS_STRUCT_SIZE 0x00080000

#define DRIVER_VM             0x00200000
#define DRIVER_VM_SIZE        0x00100000

#define TMP_FILE              0x00300000
#define TMP_FILE_SIZE         0x00100000

#define RC4_PATH "/0bbfd16a/e82bed4f"
#define TMP_FILE2             0x00400000
#define TMP_FILE2_SIZE        0x00100000

static inline void reg_sys(uint32_t index, void* ptr) {
    ((void**)(SYSCALL_TABLE))[index] = ptr;
}


static inline void sys_putchar(uint8_t c) {
    ( (void(*) (uint8_t)) (((void**)(SYSCALL_TABLE))[SYSCALL_PUTCHAR]))(c);
}

static inline void sys_puts(char* str) {
    ( (void(*) (char*)) (((void**)(SYSCALL_TABLE))[SYSCALL_PUTS]))(str);
}

static inline void sys_putchar_serial(uint8_t c) {
    ( (void(*) (uint8_t)) (((void**)(SYSCALL_TABLE))[SYSCALL_PUTCHAR_SERIAL]))(c);
}

static inline void sys_puts_serial(char* str) {
    ( (void(*) (char*)) (((void**)(SYSCALL_TABLE))[SYSCALL_PUTS_SERIAL]))(str);
}

static inline char sys_wait_for_key() {
    return ( (char(*) ()) (((void**)(SYSCALL_TABLE))[SYSCALL_WAIT_FOR_KEY]))();
}

static inline uint32_t sys_read_file(char* filePath, uint8_t* dest, uint32_t maxSize) {
    return ( (uint32_t(*) (char*, uint8_t*, uint32_t)) (((void**)(SYSCALL_TABLE))[SYSCALL_READ_FILE]))(filePath, dest, maxSize);
}

static inline uint32_t* sys_screen_index_ptr() {
    return ( (uint32_t*(*) ()) (((void**)(SYSCALL_TABLE))[SYSCALL_SCREENINDEX_PTR]))();
}

static inline uint32_t sys_execute_js(char* js) {
    return ( (uint32_t(*) (char*)) (((void**)(SYSCALL_TABLE))[SYSCALL_EXECUTE_JS]))(js);
}

static inline void* sys_execute_vm(uint8_t* code, void* arg0, void* arg1, void* arg2, void* arg3) {
    return ( (void*(*) (uint8_t*, void*,void*,void*,void*)) (((void**)(SYSCALL_TABLE))[SYSCALL_EXECUTE_VM]))(code, arg0, arg1, arg2, arg3);
}

#endif