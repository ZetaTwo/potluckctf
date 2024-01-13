#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void ignore_me() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void vuln() {
    char buf[0x20];
    printf("Enter your name: ");
    gets(buf);
}


void main(int argc, char **argv) {
    ignore_me();
    vuln();
}