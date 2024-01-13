#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "vcpu.h"
#include "util.h"
#include "debug.h"

vcpu_ctx_t *vcpu_new(void (*syscall_handler)(void *ctx, uint8_t sc))
{
    vcpu_ctx_t *ctx = malloc(sizeof(vcpu_ctx_t));
    ctx->regs[REG_INDEX_PC] = 0;
    ctx->flags = 0;
    for (int i = 0; i < GPR_COUNT; i++)
    {
        ctx->regs[i] = 0;
    }
    ctx->mappings = NULL;
    ctx->syscall_handler = syscall_handler;
    ctx->done = 0;
    ctx->flags = 0;

    return ctx;
}

void vcpu_free(vcpu_ctx_t *ctx)
{
    vcpu_mapping_t *cur = ctx->mappings;
    while (cur != NULL)
    {
        vcpu_mapping_t *next = cur->next;
        free(cur);
        cur = next;
    }

    free(ctx);
}

void vcpu_exception(vcpu_ctx_t *ctx, uint8_t ex, uint64_t addr)
{
#ifdef DEBUG
    char *exc_str[] = {
        "EXC_UNKNOWN_EXCEPTION",
        "EXC_ILLEGAL_INSTRUCTION",
        "EXC_INVALID_SYSCALL",
        "EXC_STACK_OVERFLOW",
        "EXC_STACK_UNDERFLOW",
        "EXC_READ_UNMAPPED",
        "EXC_READ_ILLEGAL",
        "EXC_WRITE_UNMAPPED",
        "EXC_WRITE_ILLEGAL",
        "EXC_EXEC_UNMAPPED",
        "EXC_EXEC_ILLEGAL"};
    vcpu_dump(ctx);
    DPRINTF("*** %s (addr=0x%llx) at PC=0x%llx\n", exc_str[ex], addr, ctx->regs[REG_INDEX_PC]);

    vcpu_mapping_t *cur = ctx->mappings;
    while (cur != NULL)
    {
        char filename[128];
        sprintf(filename, "dump_%06llx_%06llx.bin", cur->addr, cur->addr + cur->size);

        FILE *f = fopen(filename, "w");
        if (f == NULL)
        {
            printf("Error opening file %s\n", filename);
            exit(EXIT_FAILURE);
        }
        fwrite(cur->data, cur->size, 1, f);
        fclose(f);

        cur = cur->next;
    }

#endif

    exit(EXIT_FAILURE);
}

void vcpu_mem_read(vcpu_ctx_t *ctx, uint64_t addr, void *buf, uint64_t size)
{
    vcpu_mapping_t *cur = ctx->mappings;
    uint64_t offset;

    while (cur != NULL)
    {
        if (addr >= cur->addr && addr + size <= cur->addr + cur->size)
        {
            offset = addr - cur->addr;

            if (cur->prot & PROT_READ)
            {
                memcpy(buf, cur->data + offset, size);
                return;
            }
            else
            {
                vcpu_exception(ctx, EXC_READ_ILLEGAL, addr);
            }
        }
        cur = cur->next;
    }

    vcpu_exception(ctx, EXC_READ_UNMAPPED, addr);
}

void vcpu_mem_write(vcpu_ctx_t *ctx, uint64_t addr, void *buf, uint64_t size)
{
    vcpu_mapping_t *cur = ctx->mappings;
    uint64_t offset;
    while (cur != NULL)
    {
        if (addr >= cur->addr && addr + size <= cur->addr + cur->size)
        {
            offset = addr - cur->addr;

            if (cur->prot & PROT_WRITE)
            {
                memcpy(cur->data + offset, buf, size);
                return;
            }
            else
            {
                vcpu_exception(ctx, EXC_WRITE_ILLEGAL, addr);
            }
        }
        cur = cur->next;
    }

    vcpu_exception(ctx, EXC_WRITE_UNMAPPED, addr);
}

int vcpu_prot_by_addr(vcpu_ctx_t *ctx, uint64_t addr)
{
    vcpu_mapping_t *cur = ctx->mappings;
    while (cur != NULL)
    {
        if (addr >= cur->addr && addr < cur->addr + cur->size)
        {
            return cur->prot;
        }
        cur = cur->next;
    }

    return PROT_NONE;
}

int vcpu_mapping_add(vcpu_ctx_t *ctx, uint64_t addr, uint64_t size, uint8_t prot)
{
    vcpu_mapping_t *mapping = malloc(sizeof(vcpu_mapping_t));
    mapping->addr = addr;
    mapping->size = size;
    mapping->prot = prot;
    mapping->data = calloc(size, 1);
    mapping->next = NULL;

    if (ctx->mappings == NULL)
    {
        ctx->mappings = mapping;
    }
    else
    {
        vcpu_mapping_t *cur = ctx->mappings;
        while (cur->next != NULL)
        {
            cur = cur->next;
        }
        cur->next = mapping;
    }

    return 0;
}

int vcpu_exec(vcpu_ctx_t *ctx)
{
    uint8_t inc_pc = 1, opcode, b, c, d;
    uint16_t cd;
    uint64_t va, vb, rhs;

#ifdef DEBUG
    uint64_t cmpval;
#endif

    // check for EXEC access violation
    if (!(vcpu_prot_by_addr(ctx, ctx->regs[REG_INDEX_PC]) & PROT_EXEC))
    {
        vcpu_exception(ctx, EXC_EXEC_ILLEGAL, ctx->regs[REG_INDEX_PC]);
        return -1;
    }

    vcpu_mem_read(ctx, ctx->regs[REG_INDEX_PC], &opcode, 1);
    vcpu_mem_read(ctx, ctx->regs[REG_INDEX_PC] + 1, &b, 1);
    vcpu_mem_read(ctx, ctx->regs[REG_INDEX_PC] + 2, &c, 1);
    vcpu_mem_read(ctx, ctx->regs[REG_INDEX_PC] + 3, &d, 1);

    cd = (d << 8) | c;

// #define TRACE 1
#ifdef TRACE
    printf("PC: 0x%llx, opcode: 0x%x\n", ctx->regs[REG_INDEX_PC], opcode);
#endif
    switch (opcode)
    {
    case OP_NOP:
        break;

    case OP_BRANCH:
        if (
            (b == BRANCH_ALWAYS) ||
            (b == BRANCH_EQ && (ctx->flags & FLAG_EQ)) ||
            (b == BRANCH_NEQ && !(ctx->flags & FLAG_EQ)) ||
            (b == BRANCH_LT && (ctx->flags & FLAG_LT)) ||
            (b == BRANCH_LTE && (ctx->flags & FLAG_LTE)) ||
            (b == BRANCH_GT && (ctx->flags & FLAG_GT)) ||
            (b == BRANCH_GTE && (ctx->flags & FLAG_GTE)))
        {
            ctx->regs[REG_INDEX_PC] += (int16_t)cd;
            inc_pc = 0;
        }
        break;

    case OP_LOAD:
        switch (b)
        {
        case 1:
        case 2:
        case 4:
        case 8:
            vcpu_mem_read(ctx, ctx->regs[d], &ctx->regs[c], b);

            if (b == 1)
                ctx->regs[c] &= 0xff;
            if (b == 2)
                ctx->regs[c] &= 0xffff;
            if (b == 4)
                ctx->regs[c] &= 0xffffffff;
            if (b == 8)
                ctx->regs[c] &= 0xffffffffffffffff;

            break;

        default:
            return -1;
            break;
        }

        break;

    case OP_STORE:
        switch (b)
        {
        case 1:
        case 2:
        case 4:
        case 8:
            vcpu_mem_write(ctx, ctx->regs[d], &ctx->regs[c], b);
            break;

        default:
            return -1;
            break;
        }

        break;

    case OP_MOV:
        if ((b & 0xf) != ALU_SRC_REG && (b & 0xf) != ALU_SRC_IMM)
        {
            vcpu_exception(ctx, EXC_ILLEGAL_INSTRUCTION, 0);
            return -1;
        }

        if ((b & 0xf) == ALU_SRC_REG)
            ctx->regs[b >> 4] = ctx->regs[c];
        else
            ctx->regs[b >> 4] = cd;

        break;

    case OP_ALU:

        if ((b & 0xf) != ALU_SRC_REG && (b & 0xf) != ALU_SRC_IMM)
        {
            vcpu_exception(ctx, EXC_ILLEGAL_INSTRUCTION, 0);
            return -1;
        }

        rhs = d;

        if ((b & 0xf) == ALU_SRC_REG)
            rhs = ctx->regs[rhs];

        switch (b >> 4)
        {
        case ALU_ADD:
            ctx->regs[c] += rhs;
            break;

        case ALU_SUB:
            ctx->regs[c] -= rhs;
            break;

        case ALU_MUL:
            ctx->regs[c] *= rhs;
            break;

        case ALU_DIV:
            ctx->regs[c] /= rhs;
            break;

        case ALU_AND:
            ctx->regs[c] &= rhs;
            break;

        case ALU_OR:
            ctx->regs[c] |= rhs;
            break;

        case ALU_XOR:
            ctx->regs[c] ^= rhs;
            break;

        case ALU_SHL:
            ctx->regs[c] <<= rhs;
            break;

        case ALU_SHR:
            ctx->regs[c] >>= rhs;
            break;

        default:
            vcpu_exception(ctx, EXC_ILLEGAL_INSTRUCTION, 0);
            return -1;
        }

        break;

    case OP_COMPARE:
        ctx->flags = 0;

        va = ctx->regs[c];
        if ((b >> 4) == CMP_MODE_IMM8)
        {
            vb = d;
        }
        else if ((b >> 4) == CMP_MODE_REG)
        {
            vb = ctx->regs[d];
        }

        switch (b & 0x0f)
        {
        case 1:
            va &= 0xff;
            vb &= 0xff;
            break;

        case 2:
            va &= 0xffff;
            vb &= 0xffff;
            break;

        case 4:
            va &= 0xffffffff;
            vb &= 0xffffffff;
            break;

        case 8:
            va &= 0xffffffffffffffff;
            vb &= 0xffffffffffffffff;
            break;

        default:
            return -1;
        }

        if (va == vb)
            ctx->flags |= FLAG_EQ;
        else
            ctx->flags &= ~FLAG_EQ;

        if (va < vb)
            ctx->flags |= FLAG_LT;
        else
            ctx->flags &= ~FLAG_LT;

        if (va > vb)
            ctx->flags |= FLAG_GT;
        else
            ctx->flags &= ~FLAG_GT;

        if (va <= vb)
            ctx->flags |= FLAG_LTE;
        else
            ctx->flags &= ~FLAG_LTE;

        if (va >= vb)
            ctx->flags |= FLAG_GTE;
        else
            ctx->flags &= ~FLAG_GTE;

        break;

    case OP_SYSCALL:
        ctx->syscall_handler(ctx, b);

        break;

    case OP_PUSH:
        ctx->regs[REG_INDEX_SP] -= 8;
        vcpu_mem_write(ctx, ctx->regs[REG_INDEX_SP], &ctx->regs[b], 8);
        break;

    case OP_POP:
        vcpu_mem_read(ctx, ctx->regs[REG_INDEX_SP], &ctx->regs[b], 8);
        ctx->regs[REG_INDEX_SP] += 8;
        break;

    case OP_CALL:
        if (b == CALL_MODE_REL)
        {
            ctx->regs[REG_INDEX_LR] = ctx->regs[REG_INDEX_PC] + OP_SIZE;
            ctx->regs[REG_INDEX_PC] += (int16_t)cd;
            inc_pc = 0;
        }
        else if (b == CALL_MODE_REG)
        {
            ctx->regs[REG_INDEX_LR] = ctx->regs[REG_INDEX_PC] + OP_SIZE;
            ctx->regs[REG_INDEX_PC] = ctx->regs[ctx->regs[c]];
            inc_pc = 0;
        }
        else
        {
            return -1;
        }

        break;

    case OP_RET:
        ctx->regs[REG_INDEX_PC] = ctx->regs[REG_INDEX_LR];
        inc_pc = 0;
        break;

#ifdef DEBUG
    case OP_EXPECT:
        vcpu_mem_read(ctx, ctx->regs[REG_INDEX_PC] + 4, &cmpval, 8);

        if (c != 0)
        {
            if (ctx->flags != cmpval)
            {
                printf("\x1b[1mTEST ERROR\x1b[0m: expected flags to be 0x%llx, got 0x%llx\n", cmpval, ctx->flags);
                exit(EXIT_FAILURE);
                return -1;
            }
        }
        else
        {
            if (ctx->regs[b] != cmpval)
            {
                printf("\x1b[1mTEST ERROR\x1b[0m: expected R%d to be 0x%llx, got 0x%llx\n", b, cmpval, ctx->regs[b]);
                exit(EXIT_FAILURE);
                return -1;
            }
        }

        ctx->regs[REG_INDEX_PC] += 8;
        break;
#endif

    default:
        vcpu_exception(ctx, EXC_ILLEGAL_INSTRUCTION, 0);
        return -1;
    }

    if (inc_pc)
    {
        ctx->regs[REG_INDEX_PC] += OP_SIZE;
    }

    return 0;
}

#ifdef DEBUG
void vcpu_dump(vcpu_ctx_t *ctx)
{
    for (int i = 0; i < GPR_COUNT; i++)
    {
        printf("R%02d: %016llx\n", i, ctx->regs[i]);
    }
    printf("SP : %016llx\n", ctx->regs[REG_INDEX_SP]);
    printf("LR : %016llx\n", ctx->regs[REG_INDEX_LR]);
    printf("PC : %016llx\n", ctx->regs[REG_INDEX_PC]);
}
#endif