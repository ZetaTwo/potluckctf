#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// #define DEBUG
#define TEST

void sys_puts_serial(char* s) {
    printf("%s", s);
}

#include "../drivers/vm/vm.c"


int test_verify(char* inputStr) {
    
    char* fileName = "build/0bbfd16a/d1475a3a"; //"build/vm/verify.vm";
    
    FILE *filepointer;
    long size;
    char *buffer;

    filepointer = fopen(fileName,"rb");
    if( !filepointer ) {
        printf("Couldn't open the file %s\n", fileName);
        exit(1);
    }
    
    fseek(filepointer, 0L, SEEK_END);
    size = ftell(filepointer);
    rewind(filepointer);

    buffer = malloc(size+1);
    if( !buffer ) {
        fclose(filepointer);
        puts("Memory allocation failed");
        exit(1);
    }

    if(fread(buffer , size, 1 , filepointer) != 1) {
        fclose(filepointer);
        puts("Reading the file failed");
        exit(1);
    }


    MEM_SLOT appendedData[] = {};
    MEM_SLOT parameter[] = {inputStr, (MEM_SLOT)((int)strlen(inputStr)), 0, 0};
    
    int value = vm(buffer, appendedData, parameter).iV;
    
    fclose(filepointer);
    free(buffer);

    return value;
    
}

int test_rc4(unsigned char* data, int len) {
    
    char* fileName = "build/0bbfd16a/e82bed4f"; //"build/vm/RC4.vm";
    
    FILE *filepointer;
    long size;
    char *buffer;

    filepointer = fopen(fileName,"rb");
    if( !filepointer ) {
        printf("Couldn't open the file %s\n", fileName);
        exit(1);
    }
    
    fseek(filepointer, 0L, SEEK_END);
    size = ftell(filepointer);
    rewind(filepointer);

    buffer = malloc(size+1);
    if( !buffer ) {
        fclose(filepointer);
        puts("Memory allocation failed");
        exit(1);
    }

    if(fread(buffer , size, 1 , filepointer) != 1) {
        fclose(filepointer);
        puts("Reading the file failed");
        exit(1);
    }


    MEM_SLOT appendedData[] = {};
    MEM_SLOT parameter[] = {0, data, (MEM_SLOT)(len), 0, 0};
    
    int value = vm(buffer, appendedData, parameter).iV;
    
    fclose(filepointer);
    free(buffer);

    return value;
    
}

int test_aes128(unsigned char* data, int len) {
    
    char* fileName = "build/0bbfd16a/054d7b96"; //"build/vm/AES128.vm";
    
    FILE *filepointer;
    long size;
    char *buffer;

    filepointer = fopen(fileName,"rb");
    if( !filepointer ) {
        printf("Couldn't open the file %s\n", fileName);
        exit(1);
    }
    
    fseek(filepointer, 0L, SEEK_END);
    size = ftell(filepointer);
    rewind(filepointer);

    buffer = malloc(size+1);
    if( !buffer ) {
        fclose(filepointer);
        puts("Memory allocation failed");
        exit(1);
    }

    if(fread(buffer , size, 1 , filepointer) != 1) {
        fclose(filepointer);
        puts("Reading the file failed");
        exit(1);
    }


    MEM_SLOT appendedData[] = {};
    MEM_SLOT parameter[] = {0, data, (MEM_SLOT)(len), 0, 0};
    
    int value = vm(buffer, appendedData, parameter).iV;
    
    fclose(filepointer);
    free(buffer);

    return value;
    
}


int main(int argc, char** argv) {
    
    
    puts("Testing Verify");
    
    
    if(!test_verify("6c523086")) {
        puts("[VERIFY] Test Failed, Right input not detected");
        return 2;
    }
    if(test_verify("notest")) {
        puts("[VERIFY] Test Failed, Wrong input not detected");
        return 3;
    }
    
    puts("Testing RC4");
    
    // https://gchq.github.io/CyberChef/#recipe=RC4(%7B'option':'Hex','string':'0102030405060708'%7D,'Hex','Hex')&input=MDAxMTIyMzM0NDU1NjY3Nzg4OTlhYWJiY2NkZGVlZmY
    
    
    unsigned char rc4data[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    unsigned char rc4comparedata[] = {0x97,0xba, 0xa8, 0x28, 0xb4, 0xfa, 0xdf, 0x16, 0xba, 0x6b, 0x5c, 0xc9, 0x94, 0x07, 0xfb, 0x57};
    test_rc4(rc4data, sizeof(rc4data));
    
    for(int i=0;i<sizeof(rc4data);i++) {
        if(rc4data[i] != rc4comparedata[i]) {
            printf("[RC4] Test Failed %02X != %02X @ %d\n", rc4data[i], rc4comparedata[i], i);
            return 4;
        }
    }
    
    puts("Testing AES128");
    
    
    // https://gchq.github.io/CyberChef/#recipe=AES_Encrypt(%7B'option':'Hex','string':'00336699ccff326598cbfe316497cafd'%7D,%7B'option':'Hex','string':''%7D,'ECB','Hex','Hex',%7B'option':'Hex','string':''%7D)&input=MDAxMTIyMzM0NDU1NjY3Nzg4OTlhYWJiY2NkZGVlZmZmZmVlZGRjY2JiYWE5OTg4Nzc2NjU1NDQzMzIyMTEwMA
    
    unsigned char aes128data[] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
                         0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00};
    
    unsigned char aes128comparedata[] = {0xb0, 0xba, 0x6e, 0x46, 0x7b, 0x76, 0x8b, 0x5b, 0xc4, 0xf8, 0x0e, 0x2b, 0x15, 0x0d, 0x58, 0xe8, 0x06, 0xe1, 0xb3, 0xf5, 0x73, 0xe0, 0xad, 0xf3, 0x6d, 0x89, 0x1a, 0xfb, 0x8a, 0x7e, 0xd5, 0xc6};
    
    test_aes128(aes128data, sizeof(aes128data));

    for(int i=0;i<sizeof(aes128data);i++) {
        if(aes128data[i] != aes128comparedata[i]) {
            printf("[AES128] Test Failed %02X != %02X @ %d\n", aes128data[i], aes128comparedata[i], i);
            //return 5;
        }
    }

    return 0;
}