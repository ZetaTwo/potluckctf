#include "../../kernel/interface.h"

#include "vm.c"

void* runVM(uint8_t* code, void* arg0, void* arg1, void* arg2, void* arg3) {
    MEM_SLOT appendedData[] = {};
    MEM_SLOT parameter[] = {arg0, arg1, arg2, arg3, NULL};
    return vm(code, appendedData, parameter).pV;
}

void entrypoint() {
    //sys_puts_serial("Loaded VM Driver\n");
    reg_sys(SYSCALL_EXECUTE_VM, runVM);
}