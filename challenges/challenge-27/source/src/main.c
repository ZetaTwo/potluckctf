#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <signal.h>

#include "vcpu.h"
#include "util.h"
#include "debug.h"

#define SC_EXIT 0x0
#define SC_PUTCHAR 0x1
#define SC_GETCHAR 0x2
#define SC_IPC_SENDMSG 0x3
#define SC_IPC_RECVMSG 0x4
#define SC_GET_RANDOM32 0x5
#define SC_HEXDUMP 0x6
#define SC_UPTIME 0x7

int fd_fifo_tx = -1;
int fd_fifo_rx = -1;

void sc_handler(void *c, uint8_t sc)
{
    vcpu_ctx_t *ctx = (vcpu_ctx_t *)c;
    ssize_t n;
    uint8_t *buf;
    FILE *f;
    long fsize;

    switch (sc)
    {
    // args: char
    case SC_PUTCHAR:
        putchar(ctx->regs[0]);
        fflush(stdout);
        break;

    // args: char
    case SC_GETCHAR:
        ctx->regs[0] = getchar();
        break;

    // args: buf, size
    case SC_IPC_SENDMSG:
        buf = malloc(ctx->regs[1]);
        if (buf == NULL)
        {
            DPRINTF("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }

        vcpu_mem_read(ctx, ctx->regs[0], buf, ctx->regs[1]);
        n = write(fd_fifo_tx, buf, ctx->regs[1]);
        free(buf);

        if (n <= 0)
        {
            DPRINTF("Error writing to fifo\n");
            exit(EXIT_FAILURE);
        }

        ctx->regs[0] = n;
        break;

    // args: buf, size
    case SC_IPC_RECVMSG:
        buf = malloc(ctx->regs[1]);

        if (buf == NULL)
        {
            DPRINTF("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }

        n = read(fd_fifo_rx, buf, ctx->regs[1]);
        if (n <= 0)
        {
            free(buf);
            DPRINTF("Error reading from fifo\n");
            exit(EXIT_FAILURE);
        }

        vcpu_mem_write(ctx, ctx->regs[0], buf, ctx->regs[1]);
        free(buf);

        ctx->regs[0] = n;

        break;

    case SC_GET_RANDOM32:
        ctx->regs[0] = rand();
        break;

#ifdef DEBUG
    case SC_HEXDUMP:
        buf = malloc(ctx->regs[1]);

        if (buf == NULL)
        {
            DPRINTF("Error allocating memory\n");
            exit(EXIT_FAILURE);
        }

        vcpu_mem_read(ctx, ctx->regs[0], buf, ctx->regs[1]);
        hexdump(buf, ctx->regs[1]);
        free(buf);

        break;
#endif

    case SC_UPTIME:
        if (ctx->is_master)
        {
            system("uptime > /tmp/u");
            f = fopen("/tmp/u", "rb");
            fseek(f, 0L, SEEK_END);
            fsize = ftell(f);
            fseek(f, 0L, SEEK_SET);
            buf = malloc(fsize);
            fread(buf, fsize, 1, f);
            fclose(f);
            vcpu_mem_write(ctx, ctx->regs[0], buf, fsize);
            free(buf);
            ctx->regs[0] = 0;
        }
        else
        {
            ctx->regs[0] = 1;
        }

        break;

    case SC_EXIT:
#ifdef DEBUG
        vcpu_dump(ctx);
        printf("\n");
#endif
        ctx->done = 1;
        break;

    default:
        DPRINTF("*** Unknown syscall %d\n", sc);
        exit(EXIT_FAILURE);
    }
}

void usage(char *prog)
{
    printf("usage: %s <code.bin> <fifo_path> <is_master>\n", prog);
    exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
    if (argc != 4 && argc != 2)
    {
        usage(argv[0]);
    }

    srand(time(NULL));
    vcpu_ctx_t *ctx = vcpu_new(sc_handler);

    if (argc == 4)
    {
        signal(SIGPIPE, SIG_IGN);

        ctx->is_master = atoi(argv[3]);

        char fifo_path_master[256];
        char fifo_path_slave[256];
        sprintf(fifo_path_master, "%s_master", argv[2]);
        sprintf(fifo_path_slave, "%s_slave", argv[2]);

        char *fifo_path_tx = ctx->is_master ? fifo_path_master : fifo_path_slave;
        char *fifo_path_rx = ctx->is_master ? fifo_path_slave : fifo_path_master;

        DPRINTF("creating TX fifo %s\n", fifo_path_tx);
        struct stat st;
        if (stat(fifo_path_tx, &st) == 0)
        {
            unlink(fifo_path_tx);
        }

        if (mkfifo(fifo_path_tx, 0666) == -1)
        {
            printf("error creating %s\n", fifo_path_tx);
            exit(EXIT_FAILURE);
        }

        if (ctx->is_master)
        {
            DPRINTF("open TX fifo %s\n", fifo_path_tx);
            fd_fifo_tx = open(fifo_path_tx, O_WRONLY);
            if (fd_fifo_tx == -1)
            {
                DPRINTF("error opening %s\n", fifo_path_tx);
                exit(EXIT_FAILURE);
            }
            DPRINTF("TX fifo opened\n");

            DPRINTF("open RX fifo %s\n", fifo_path_rx);
            fd_fifo_rx = open(fifo_path_rx, O_RDONLY);
            if (fd_fifo_rx == -1)
            {
                DPRINTF("error opening rx fifo '%s'.. \n", fifo_path_rx);
                return -1;
            }
        }
        else
        {
            DPRINTF("open RX fifo %s\n", fifo_path_rx);
            fd_fifo_rx = open(fifo_path_rx, O_RDONLY);
            if (fd_fifo_rx == -1)
            {
                DPRINTF("Error opening rx fifo '%s'.. \n", fifo_path_rx);
                return -1;
            }

            DPRINTF("open TX fifo %s\n", fifo_path_tx);
            fd_fifo_tx = open(fifo_path_tx, O_WRONLY);
            if (fd_fifo_tx == -1)
            {
                DPRINTF("error opening %s\n", fifo_path_tx);
                exit(EXIT_FAILURE);
            }
            DPRINTF("TX fifo opened\n");
        }
    }

    long code_size;
    uint8_t *code = slurp_file(argv[1], &code_size);

    if (memcmp(code, "UNICORN\x00", 8) != 0)
    {
        DPRINTF("invalid code file\n");
        exit(EXIT_FAILURE);
    }

    uint16_t *mapping_info = (uint16_t *)(code + 10);
    uint16_t mapping_cnt = *(uint16_t *)(code + 8);

    for (int i = 0; i < mapping_cnt; i++)
    {
        uint16_t start = mapping_info[0];
        uint16_t size = mapping_info[1];
        uint16_t prot = mapping_info[2];
        if (i == 0)
        {
            prot |= PROT_WRITE;
        }
        vcpu_mapping_add(ctx, start, size, prot);
        ctx->regs[REG_INDEX_SP] = start + size;
        mapping_info += 3;
    }

    uint8_t *text_start = code + 10 + mapping_cnt * 6;
    uint32_t text_size = code_size - (10 + (mapping_cnt * 6));

    vcpu_mem_write(ctx, ctx->mappings->addr, text_start, text_size);
    // .text cant be writable
    ctx->mappings->prot &= ~PROT_WRITE;
    free(code);

    while (1)
    {
        if (vcpu_exec(ctx) != 0)
        {
            DPRINTF("*** error executing instruction at PC=0x%llx\n", ctx->regs[REG_INDEX_PC]);
            exit(EXIT_FAILURE);
            break;
        }
        if (ctx->done)
        {
            break;
        }
    }

    close(fd_fifo_tx);
    close(fd_fifo_rx);

    return EXIT_SUCCESS;
}