#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "util.h"

void hexdump(void *ptr, int buflen)
{
    unsigned char *buf = (unsigned char *)ptr;
    int i, j;
    for (i = 0; i < buflen; i += 16)
    {
        printf("%06x: ", i);
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%02x ", buf[i + j]);
            else
                printf("   ");
        printf(" ");
        for (j = 0; j < 16; j++)
            if (i + j < buflen)
                printf("%c", isprint(buf[i + j]) ? buf[i + j] : '.');
        printf("\n");
    }
}

uint8_t *slurp_file(char *filename, long *fsize)
{
    FILE *f = fopen(filename, "r");
    if (f == NULL)
    {
        printf("Error opening file %s\n", filename);
        exit(EXIT_FAILURE);
    }

    fseek(f, 0L, SEEK_END);

    *fsize = ftell(f);
    fseek(f, 0L, SEEK_SET);
    uint8_t *buf = malloc(*fsize);
    fread(buf, *fsize, 1, f);
    fclose(f);

    return buf;
}

uint16_t le16(uint8_t *buf)
{
    return buf[0] | (buf[1] << 8);
}