#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <errno.h>
#include <pthread.h>

#define MCODE_MAX 0x10000
#define MCODE_LINE 1+8+8+8

char *mcode[5] = {0, };
int mcode_size[5] = {0, };
int mcode_mutex[5] = {0, };
int mcode_count = -1;

void err(){
    exit(-1);
}

typedef enum {
    OPC_NONE,
    OPC_MOV,
    OPC_SUB,
    OPC_ADD,
    OPC_MUL,
    OPC_SQR,
    OPC_SHL,
    OPC_SHR,
    OPC_AND,
    OPC_OR,
    OPC_NOT,
    OPC_ALLOC,
    OPC_WRITE_MEM,
    OPC_READ_MEM,
    OPC_COPY,
    OPC_PRINT,
    OPC_PAUSE,
    OPC_LOCK,
    OPC_UNLOCK,
    OPC_MOV2,
    OPC_AND2,
    OPC_OR2,
} OpcType;

typedef enum {
    REG_SCALAR,
    REG_PTR,
    REG_DANGER,
} RegType;

OpcType getOpcType(const char* opc) {
    if (strcmp(opc, "mov") == 0) return OPC_MOV;
    if (strcmp(opc, "sub") == 0) return OPC_SUB;
    if (strcmp(opc, "add") == 0) return OPC_ADD;
    if (strcmp(opc, "shl") == 0) return OPC_SHL;
    if (strcmp(opc, "shr") == 0) return OPC_SHR;
    if (strcmp(opc, "mul") == 0) return OPC_MUL;
    if (strcmp(opc, "sqr") == 0) return OPC_SQR;
    if (strcmp(opc, "or") == 0) return OPC_OR;
    if (strcmp(opc, "and") == 0) return OPC_AND;
    if (strcmp(opc, "and") == 0) return OPC_NOT;
    if (strcmp(opc, "write") == 0) return OPC_WRITE_MEM;
    if (strcmp(opc, "read") == 0) return OPC_READ_MEM;
    if (strcmp(opc, "copy") == 0) return OPC_COPY;
    if (strcmp(opc, "print") == 0) return OPC_PRINT;
    if (strcmp(opc, "alloc") == 0) return OPC_ALLOC;
    if (strcmp(opc, "pause") == 0) return OPC_PAUSE;
    if (strcmp(opc, "lock") == 0) return OPC_LOCK;
    if (strcmp(opc, "unlock") == 0) return OPC_UNLOCK;
    if (strcmp(opc, "mov2") == 0) return OPC_MOV2;
    if (strcmp(opc, "and2") == 0) return OPC_AND2;
    if (strcmp(opc, "or2") == 0) return OPC_OR2;
    
    return OPC_NONE;
}

unsigned long long parseRegister(const char *reg) {
    if (reg[0] != 'r' || strlen(reg) != 2) {
        write(1, "Error: parseRegister Error\n", 27); err();
    }

    if (reg[1] < '0' || reg[1] > '8') {
        write(1, "Error: parseRegister Error\n", 27); err();
    }

    return reg[1] - '0';
}


unsigned long long parseHex(const char *hexStr) {
    if(hexStr==NULL){
        write(1, "Error: parseHex Error\n", 22); err();
    }
    char *end;
    errno = 0;
    unsigned long long num = strtoull(hexStr, &end, 16);

    if (errno == ERANGE && num == ULLONG_MAX) {
        write(1, "Error: parseHex Error\n", 22); err();
    }
    if (errno != 0 && num == 0) {
        write(1, "Error: parseHex Error\n", 22); err();
    }
    if (end == hexStr) {
        write(1, "Error: parseHex Error\n", 22); err();
    }
    if (*end != '\0') {
        write(1, "Error: parseHex Error\n", 22); err();
    }

    return num;
}

void push_mcode(char *buf){
    if(mcode_size[mcode_count] > MCODE_MAX-0x10){
        write(1, "Error: push_mcode Error\n", 24); err();
    }
    memcpy((mcode[mcode_count]+mcode_size[mcode_count]), buf, MCODE_LINE);
    mcode_size[mcode_count] = mcode_size[mcode_count] + MCODE_LINE;
}

void generate_mcode(char *opc, char *arg1, char *arg2, char *arg3){
    OpcType opc_ = getOpcType(opc);
    unsigned long long arg1_ = 0;
    unsigned long long arg2_ = 0;
    unsigned long long arg3_ = 0;
    char mcode_buf[MCODE_LINE] = {0, };

    switch(opc_) {
        case OPC_NONE:
            write(1, "Error: Unknown opc\n", 19); err();
        case OPC_MOV:
        case OPC_SUB:
        case OPC_ADD:
        case OPC_SHL:
        case OPC_SHR:
        case OPC_OR:
        case OPC_AND:
        case OPC_MUL:
        case OPC_SQR:
        case OPC_ALLOC:
            arg1_ = parseRegister(arg1);
            arg2_ = parseHex(arg2);
            mcode_buf[0] = (char)opc_;
            memcpy(&mcode_buf[1],&arg1_,8);
            memcpy(&mcode_buf[9],&arg2_,8);
            break;
        case OPC_WRITE_MEM:
        case OPC_READ_MEM:
        case OPC_COPY:
            arg1_ = parseRegister(arg1);
            arg2_ = parseRegister(arg2);
            arg3_ = parseHex(arg3);
            mcode_buf[0] = (char)opc_;
            memcpy(&mcode_buf[1],&arg1_,8);
            memcpy(&mcode_buf[9],&arg2_,8);
            memcpy(&mcode_buf[17],&arg3_,8);
            break;
        case OPC_PRINT:
            arg1_ = parseRegister(arg1);
            arg2_ = parseHex(arg2);
            arg3_ = parseHex(arg3);
            mcode_buf[0] = (char)opc_;
            memcpy(&mcode_buf[1],&arg1_,8);
            memcpy(&mcode_buf[9],&arg2_,8);
            memcpy(&mcode_buf[17],&arg3_,8);
            break;
        case OPC_PAUSE:
        case OPC_LOCK:
            mcode_buf[0] = (char)opc_;
            break;
        case OPC_UNLOCK:
            arg1_ = parseHex(arg1);
            mcode_buf[0] = (char)opc_;
            memcpy(&mcode_buf[1],&arg1_,8);
            break;
        case OPC_NOT:
            arg1_ = parseRegister(arg1);
            mcode_buf[0] = (char)opc_;
            memcpy(&mcode_buf[1],&arg1_,8);
            break;
        case OPC_MOV2:
        case OPC_AND2:
        case OPC_OR2:
            arg1_ = parseRegister(arg1);
            arg2_ = parseRegister(arg2);
            mcode_buf[0] = (char)opc_;
            memcpy(&mcode_buf[1],&arg1_,8);
            memcpy(&mcode_buf[9],&arg2_,8);
            break;
    }

    push_mcode(mcode_buf);
}

int parser(char *input) {
    char *line;
    char *saveptr1;
    char *opc;
    char *arg[3];
    char *saveptr2;

    line = strtok_r(input, "\n", &saveptr1);
    while (line != NULL) {
        opc = strtok_r(line, " ", &saveptr2);
        arg[0] = strtok_r(NULL, ", ", &saveptr2);

        char *next_token = strtok_r(NULL, ", ", &saveptr2);
        arg[1] = next_token ? next_token : NULL;

        char *next_token2 = strtok_r(NULL, ", ", &saveptr2);
        arg[2] = next_token2 ? next_token2 : NULL;

        //printf("Opc: %s, Arg1: %s, Arg2: %s, Arg3: %s\n", opc, arg[0], arg[1], arg[2]);

        if(!strcmp(opc,"thread")){
            if(mcode_count == 4){
                write(1, "Error: Too many thread\n", 23); err();
            }
            mcode_count++;
            mcode[mcode_count] = calloc(1, MCODE_MAX);
        } else {
            if(mcode_count == - 1){
                write(1, "Error: There is no thread\n", 26); err();
            } else {
                generate_mcode(opc, arg[0], arg[1], arg[2]);
            }
        }

        line = strtok_r(NULL, "\n", &saveptr1);
    }

    return 0;
}



struct Regs {
    long long unsigned reg[8];
    RegType reg_type[8];
    long long unsigned ptr_size[8];
};

void *vm(void* num){
    //printf("thread: %d\n", *(int*)num);
    int nothing;
    struct Regs regs;
    char *thread_mcode = mcode[*(int*)num];

    OpcType opc;
    long long unsigned arg1;
    long long unsigned arg2;
    long long unsigned arg3;

    for(int sp = 0; sp < mcode_size[*(int*)num]; sp = sp + MCODE_LINE){
        opc = (OpcType)thread_mcode[sp];
        memcpy(&arg1, &thread_mcode[sp+1], 8);
        memcpy(&arg2, &thread_mcode[sp+9], 8);
        memcpy(&arg3, &thread_mcode[sp+17], 8);
        //printf("%d. Opc: %d, Arg1: %llu, Arg2: %llu, Arg3: %llu\n", *(int*)num, opc, arg1, arg2, arg3);

        switch(opc) {
            case OPC_NONE:
                return NULL;
            case OPC_MOV:
                regs.reg[arg1] = arg2;
                regs.reg_type[arg1] = REG_SCALAR;
                break;
            case OPC_SUB:
                regs.reg[arg1] -= arg2;
                if(regs.reg_type[arg1]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_ADD:
                regs.reg[arg1] += arg2;
                if(regs.reg_type[arg1]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_SHL:
                regs.reg[arg1] <<= arg2;
                if(regs.reg_type[arg1]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_SHR:
                regs.reg[arg1] >>= arg2;
                if(regs.reg_type[arg1]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_OR:
                regs.reg[arg1] |= arg2;
                if(regs.reg_type[arg1]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_AND:
                regs.reg[arg1] &= arg2;
                if(regs.reg_type[arg1]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_NOT:
                regs.reg[arg1] = ~regs.reg[arg1];
                if(regs.reg_type[arg1]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_MUL:
                regs.reg[arg1] *= arg2;
                if(regs.reg_type[arg1]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_SQR:
                long long unsigned sqr_count = regs.reg[arg1];
                regs.reg[arg1] = arg2;
                for(long long unsigned i=0; i < sqr_count; i++){
                    regs.reg[arg1] *= regs.reg[arg1];
                }
                if(regs.reg_type[arg1]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_ALLOC:
                if(arg2 < 8){
                    write(1, "Error: Runtime Error\n", 21); err();
                }
                regs.reg[arg1] = (long long unsigned)calloc(1, arg2);
                regs.reg_type[arg1] = REG_PTR;
                regs.ptr_size[arg1] = arg2;
                if(regs.reg[arg1] == 0){
                    write(1, "Error: Runtime Error\n", 21); err();
                }
                break;
            case OPC_WRITE_MEM:
                if(regs.reg_type[arg1] == REG_PTR && (unsigned int)arg3 < (regs.ptr_size[arg1]-8)){
                    memcpy((void *)regs.reg[arg1]+(unsigned int)arg3, &regs.reg[arg2], 8);
                } else {
                    write(1, "Error: Runtime Error\n", 21); err();
                }
                break;
            case OPC_READ_MEM:
                if(regs.reg_type[arg1] == REG_PTR && (unsigned int)arg3 < (regs.ptr_size[arg1]-8)){
                    memcpy(&regs.reg[arg2], (void *)regs.reg[arg1]+(unsigned int)arg3, 8);
                } else {
                    write(1, "Error: Runtime Error\n", 21); err();
                }
                break;
            case OPC_COPY:
                if(regs.reg_type[arg1] == REG_PTR && regs.reg_type[arg2] == REG_PTR && (unsigned short)arg3 < regs.ptr_size[arg1] && (unsigned short)arg3 < regs.ptr_size[arg2]){
                    memcpy((void *)regs.reg[arg1], (void *)regs.reg[arg2], (unsigned short)arg3);
                    ((char *)regs.reg[arg1])[arg3] = 0;
                } else {
                    write(1, "Error: Runtime Error\n", 21); err();
                }
                break;
            case OPC_PRINT:
                if(regs.reg_type[arg1] == REG_PTR && (arg2+arg3) < (regs.ptr_size[arg1]) && (arg2+arg3) > arg2){
                    write(1, (void *)regs.reg[arg1]+arg2, arg3);
                } else {
                    write(1, "Error: Runtime Error\n", 21); err();
                }
                break;
            case OPC_PAUSE:
                getchar();
                break;
            case OPC_LOCK:
                mcode_mutex[*(int*)num] = 1;
                while(mcode_mutex[*(int*)num]){
                    nothing++;
                }
                break;
            case OPC_UNLOCK:
                if(arg1 < 5){
                    mcode_mutex[arg1] = 0;
                } else {
                    write(1, "Error: Runtime Error\n", 21); err();
                }
                break;
            case OPC_MOV2:
                regs.reg[arg1] = regs.reg[arg2];
                regs.reg_type[arg1] = regs.reg_type[arg2];
                break;
            case OPC_AND2:
                regs.reg[arg1] &= regs.reg[arg2];
                if(regs.reg_type[arg1]==REG_PTR || regs.reg_type[arg2]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;
            case OPC_OR2:
                regs.reg[arg1] |= regs.reg[arg2];
                if(regs.reg_type[arg1]==REG_PTR || regs.reg_type[arg2]==REG_PTR){
                    regs.reg_type[arg1]==REG_DANGER;
                }
                break;

        }
    }

}

void vmRun(){
    pthread_t thread[5];
    int i_[5];
    for(int i=0; i<=mcode_count; i++){
        i_[i] = i;
        pthread_create(&thread[i], NULL, vm, (void*) &i_[i]);

    }

    for(int i=0; i<=mcode_count; i++){
        pthread_join(thread[i], NULL);
    }
}

void init(){
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
}

int main(int argc, char *argv[]){
    init();
    if(argc != 2){
        write(1, "Usage: ./myP1G code.txt\n", 24);
        return -1;
    }

    int fd = open(argv[1], O_RDONLY);
    if(fd == -1){
        write(1, "Error: Open failed\n", 20);
        return -1;
    }
    
    char *buf = calloc(1, MCODE_MAX*2);
    read(fd, buf, MCODE_MAX*2);
    parser(buf);

    vmRun();

    return 1;
}