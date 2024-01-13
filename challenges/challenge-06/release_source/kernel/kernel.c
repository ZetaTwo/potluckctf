#include <stdint.h>
#include "pxe.h"
#include "kernel.h"
#include "helper.h"
#include "interface.h"



void challenge() {

    uint32_t len;
    
    // load js driver
    len = readFile("/e410c307/0bafe770", ( uint8_t*)DRIVER_JS, DRIVER_JS_SIZE);
    ((void(*)())DRIVER_JS)();
    
    // load vm driver
    len = readFile("/e410c307/c03bc6b3", ( uint8_t*)DRIVER_VM, DRIVER_VM_SIZE);
    ((void(*)())DRIVER_VM)();
    
    len = sys_read_file("/15c93851/844af54e", (uint8_t*)TMP_FILE, TMP_FILE_SIZE);
    ((uint8_t*)TMP_FILE)[len] = 0;
    
    // Decrypt js file
    sys_read_file(RC4_PATH, (uint8_t*)TMP_FILE2, TMP_FILE2_SIZE);
    sys_execute_vm((uint8_t*)TMP_FILE2, 0, (char*)TMP_FILE, (void*)len, 0);
    
    void* res = (void*)sys_execute_js((char*)TMP_FILE);


    
}
extern uint32_t screenIndex;

uint32_t* getScreenIndex() {
    return &screenIndex;
}


void entrypoint(SEGOFF16 pxe) {
    
    activateA20(); // another method of activating the a20 line (this works for my test devices)
    
    // Clearing the Screen before is optional, not doing so leaves some debug information
    
    puts(" Booting...\n");  // Verify Linking got the offset correct

    initPXE(pxe);
    
    reg_sys(SYSCALL_PUTCHAR, putchar);
    reg_sys(SYSCALL_PUTS, puts);
    reg_sys(SYSCALL_PUTCHAR_SERIAL, putchar_serial);
    reg_sys(SYSCALL_PUTS_SERIAL, puts_serial);
    reg_sys(SYSCALL_WAIT_FOR_KEY, waitForKey);
    reg_sys(SYSCALL_READ_FILE, readFile);
    reg_sys(SYSCALL_SCREENINDEX_PTR, getScreenIndex);
    
    challenge();
    
    puts("done");
    while(1) { wait(); }
}
