#include <stdio.h>
#include <stdint.h>

//#define DEBUG
//#define DEBUG2

#ifndef TEST
#include "../../kernel/helper.h"
#endif

#define OP_CONST   0x00 // CONST <X> - 00 XX XX XX RR XX
#define OP_LOAD8   0x01 // LOAD <SLOT S> - 01 SS SS 00 RR 00
#define OP_LOAD16  0x02
#define OP_LOAD32  0x03
#define OP_LOADP   0x04
#define OP_PLOAD8  0x05 // parameter load
#define OP_PLOAD16 0x06
#define OP_PLOAD32 0x07
#define OP_PLOADP  0x08
#define OP_STORE8  0x09 // STORE <SLOT S> <STORE CC> - 02 SS SS 00 CC 00
#define OP_STORE16 0x0A 
#define OP_STORE32 0x0B 
#define OP_STOREP  0x0C 
#define OP_ALOAD8 0x0D // ALOAD  <ARRAY A> <INDEX I> - 03 AA II 00 RR 00
#define OP_ALOAD16 0x0E
#define OP_ALOAD32 0x0F
#define OP_ALOADP 0x10
#define OP_ASTORE8 0x11 // ASTORE <ARRAY A> <INDEX I> <DATA D> - 04 AA II 00 DD 00
#define OP_ASTORE16 0x12
#define OP_ASTORE32 0x13
#define OP_ASTOREP 0x14
#define OP_NOT 0x15 // MATH <OP1 A> <OP2 B> - 05 AA BB 00 RR 00
#define OP_NEG 0x16
#define OP_NOP 0x17
#define OP_ADD 0x18
#define OP_SUB 0x19
#define OP_MUL 0x1A
#define OP_DIV 0x1B
#define OP_MOD 0x1C
#define OP_AND 0x1D
#define OP_OR 0x1E
#define OP_XOR 0x1F
#define OP_SHR 0x20
#define OP_USHR 0x21
#define OP_SHL 0x22
#define OP_COMPARE_EQUAL 0x23 // COMPARE <OP1 A> <OP2 B> <CONDITIONALJUMP J> - 06 AA BB JJ JJ 00
#define OP_COMPARE_NOTEQUAL 0x24
#define OP_COMPARE_LESSTHAN 0x25
#define OP_COMPARE_LESSEQUAL 0x26
#define OP_COMPARE_GREATERTHAN 0x27
#define OP_COMPARE_GREATEREQUAL 0x28
#define OP_SWITCH 0x29 // SWITCH <SWITCHVAR S> - 07 SS 00 00 00 00
#define OP_JUMP 0x2A // JUMP <JUMP J> 08 00 00 JJ JJ 00
#define OP_RETURN 0x2B // RETURN < <VALUE V> 09 VV 00 00 00 00
#define OP_RETURNV 0x2C 
#define OP_ALLOC8 0x2D // ALLOC <COUNT CC> - 2D CC 00 00 RR 00
#define OP_ALLOC16 0x2E
#define OP_ALLOC32 0x2F
#define OP_ALLOCP 0x30
#define OP_PSTORE8  0x31 // STORE <SLOT S> <STORE CC> - 02 SS SS 00 CC 00
#define OP_PSTORE16 0x32 
#define OP_PSTORE32 0x33
#define OP_PSTOREP  0x34 
#define OP_OCONST  0x35  // OCONST <X> - 00 XX XX XX RR XX


#define OP_CUSTOM_PREPCALL  0x36  // PREPCALL <X> <X> <X> <X> - 00 XX XX XX RR XX
#define OP_CUSTOM_CALL      0x37  // CALL <X> - 00 XX 00 00 RR 00


union MEM_SLOT {
  void* pV;
  int   iV;
  short sV;
  char  bV;
};

typedef union MEM_SLOT MEM_SLOT;

#define ALLOCATION_BUFFER_SIZE 0x400

MEM_SLOT vm(char* program, MEM_SLOT* appendedData, MEM_SLOT* pars) {
    
        #if defined(DEBUG) || defined(DEBUG2)
            char debugBuffer[256];
        #endif
		MEM_SLOT memory[0x100*2];
        char* allocationBuffer[ALLOCATION_BUFFER_SIZE];
        unsigned int allocationBufferIndex = 0;
        
		int pc = 0;
		while(1) {
			int opcode = program[pc]&0xFF;
            int index;
			int data;
			int memslot;
			int op1;
			int op2;
            int op3;
            int op4;
			short jumpPosition;
			int stackslot;
			
			data = (program[pc+1]&0xFF)|((program[pc+2]&0xFF)<<8)|((program[pc+3]&0xFF)<<16)|(program[pc+5]<<24);
			op1     = program[pc+1]&0xFF;
			op2     = program[pc+2]&0xFF;
			op3     = program[pc+3]&0xFF;
			op4     = program[pc+5]&0xFF;
			jumpPosition = (short) ((program[pc+3]&0xFF) | (program[pc+4]<<8));
			memslot = (program[pc+1]&0xFF)|((program[pc+2]&0xFF)<<8);
			stackslot = (program[pc+4]&0xFF);
			switch(opcode) {
			case OP_CONST:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]CONST = %d\n", pc, stackslot, data);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = data;
				break;
			case OP_LOAD8:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]LOAD8 = %d\n", pc, stackslot, memory[memslot+0x100].bV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = memory[memslot+0x100].bV;
				break;
			case OP_LOAD16:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]LOAD16 = %d\n", pc, stackslot, memory[memslot+0x100].sV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = memory[memslot+0x100].sV;
				break;
			case OP_LOAD32:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]LOAD32 = %d\n", pc, stackslot, memory[memslot+0x100].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = memory[memslot+0x100].iV;
				break;
			case OP_LOADP:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]LOADP = %p\n", pc, stackslot, memory[memslot+0x100].pV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].pV = memory[memslot+0x100].pV;
				break;
			case OP_PLOAD8:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]PLOAD8 = %d @ %d\n", pc, stackslot, pars[memslot].bV, memslot);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = pars[memslot].bV;
				break;
			case OP_PLOAD16:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]PLOAD16 = %d @ %d\n", pc, stackslot, pars[memslot].sV, memslot);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = pars[memslot].sV;
				break;
			case OP_PLOAD32:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]PLOAD32 = %d @ %d\n", pc, stackslot, pars[memslot].iV, memslot);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = pars[memslot].iV;
				break;
			case OP_PLOADP:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]PLOADP = %p @ %d\n", pc, stackslot, pars[memslot].pV, memslot);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].pV = pars[memslot].pV;
				break;
			case OP_STORE8:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]STORE8 = %d\n", pc, memslot+0x100, (memory[stackslot].iV)&0xFF);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[memslot+0x100].iV = (memory[stackslot].iV)&0xFF;
				break;
			case OP_STORE16:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]STORE16 = %d\n", pc, memslot+0x100, (memory[stackslot].iV)&0xFFFF);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[memslot+0x100].iV = (memory[stackslot].iV)&0xFFFF;
				break;
			case OP_STORE32:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]STORE32 = %d\n", pc, memslot+0x100, memory[stackslot].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[memslot+0x100].iV = memory[stackslot].iV;
				break;
			case OP_STOREP:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]STOREP = %p\n", pc, memslot+0x100, memory[stackslot].pV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[memslot+0x100].pV = memory[stackslot].pV;
				break;
			case OP_PSTORE8:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x pars[%d]PSTORE8 = %d\n", pc, memslot, memory[stackslot].iV&0xFF);
                    sys_puts_serial(debugBuffer);
                #endif
				pars[memslot].iV = memory[stackslot].iV&0xFF;
				break;
			case OP_PSTORE16:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x pars[%d]PSTORE16 = %d\n", pc, memslot, memory[stackslot].iV&0xFFFF);
                    sys_puts_serial(debugBuffer);
                #endif
				pars[memslot].iV = memory[stackslot].iV&0xFFFF;
				break;
			case OP_PSTORE32:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x pars[%d]PSTORE32 = %d\n", pc, memslot, memory[stackslot].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				pars[memslot].iV = memory[stackslot].iV;
				break;
			case OP_PSTOREP:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x pars[%d]PSTOREP = %p\n", pc, memslot, memory[stackslot].pV);
                    sys_puts_serial(debugBuffer);
                #endif
				pars[memslot].pV = memory[stackslot].pV;
				break;
			case OP_ALOAD8:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]ALOAD8 = %d\n", pc, stackslot, ((char*)memory[op1].pV)[(memory[op2].iV)]);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = ((char*)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ALOAD16:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]ALOAD16 = %d\n", pc, stackslot, ((short*)memory[op1].pV)[(memory[op2].iV)]);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = ((short*)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ALOAD32:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]ALOAD32 = %d\n", pc, stackslot, ((int*)memory[op1].pV)[(memory[op2].iV)]);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = ((int*)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ALOADP:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]ALOADP = %p\n", pc, stackslot, ((void**)memory[op1].pV)[(memory[op2].iV)]);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].pV = ((void**)memory[op1].pV)[(memory[op2].iV)];
				break;
			case OP_ASTORE8:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%p]ASTORE8 = %d\n", pc, ((char*)memory[op1].pV) + (memory[op2].iV), memory[stackslot].bV);
                    sys_puts_serial(debugBuffer);
                #endif
                ((char*)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].bV;
				break;
			case OP_ASTORE16:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%p]ASTORE16 = %d\n", pc, ((char*)memory[op1].pV) + (memory[op2].iV), memory[stackslot].sV);
                    sys_puts_serial(debugBuffer);
                #endif
				((short*)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].sV;
				break;
			case OP_ASTORE32:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%p]ASTORE32 = %d\n", pc, ((char*)memory[op1].pV) + (memory[op2].iV), memory[stackslot].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				((int*)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].iV;
				break;
			case OP_ASTOREP:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%p]ASTOREP = %p\n", pc, ((char*)memory[op1].pV) + (memory[op2].iV), memory[stackslot].pV);
                    sys_puts_serial(debugBuffer);
                #endif
				((void**)memory[op1].pV)[(memory[op2].iV)] = memory[stackslot].pV;
				break;
			case OP_NOT:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]NOT = %d\n", pc, stackslot, memory[op1].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = ~(memory[op1].iV);
				break;
			case OP_NEG:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]NEG = %d\n", pc, stackslot, memory[op1].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = -(memory[op1].iV);
				break;
			case OP_NOP:
                // SKIP NOPS IN DEBUG PRINT
				memory[stackslot].iV = (memory[op1].iV);
				break;
			case OP_ADD:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]ADD = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) + (memory[op2].iV);
				break;
			case OP_SUB:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]SUB = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) - (memory[op2].iV);
				break;
			case OP_MUL:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]MUL = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) * (memory[op2].iV);
				break;
			case OP_DIV:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]DIV = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) / (memory[op2].iV);
				break;
			case OP_MOD:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]MOD = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) % (memory[op2].iV);
				break;		
			case OP_AND:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]AND = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) & (memory[op2].iV);
				break;	
			case OP_OR:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]OR = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) | (memory[op2].iV);
				break;	
			case OP_XOR:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]XOR = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) ^ (memory[op2].iV);
				break;	
			case OP_SHR:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]SHR = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) >> (memory[op2].iV);
				break;	
			case OP_USHR:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]USHR = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (((unsigned int)memory[op1].iV) >> ((unsigned int)memory[op2].iV));
				break;
			case OP_SHL:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]SHL = %d, %d\n", pc, stackslot, memory[op1].iV, memory[op2].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].iV = (memory[op1].iV) << (memory[op2].iV);
				break;
			case OP_COMPARE_EQUAL:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x COMPARE_EQUAL = %d, %d => %08x\n", pc, memory[op1].iV, memory[op2].iV, pc+((int)jumpPosition-6));
                    sys_puts_serial(debugBuffer);
                #endif
				if(memory[op1].iV == memory[op2].iV)
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_NOTEQUAL:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x COMPARE_NOTEQUAL = %d, %d => %08x\n", pc, memory[op1].iV, memory[op2].iV, pc+((int)jumpPosition-6));
                    sys_puts_serial(debugBuffer);
                #endif
				if(memory[op1].iV != memory[op2].iV)
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_LESSTHAN:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x COMPARE_LESSTHAN = %d, %d => %08x\n", pc, memory[op1].iV, memory[op2].iV, pc+((int)jumpPosition-6));
                    sys_puts_serial(debugBuffer);
                #endif
				if((memory[op1].iV) < (memory[op2].iV))
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_LESSEQUAL:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x COMPARE_LESSEQUAL = %d, %d => %08x\n", pc, memory[op1].iV, memory[op2].iV, pc+((int)jumpPosition-6));
                    sys_puts_serial(debugBuffer);
                #endif
				if((memory[op1].iV) <= (memory[op2].iV))
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_GREATERTHAN:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x COMPARE_GREATERTHAN = %d, %d => %08x\n", pc, memory[op1].iV, memory[op2].iV, pc+((int)jumpPosition-6));
                    sys_puts_serial(debugBuffer);
                #endif
				if((memory[op1].iV) > (memory[op2].iV))
					pc += ((int)jumpPosition-6);
				break;
			case OP_COMPARE_GREATEREQUAL:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x COMPARE_GREATEREQUAL = %d, %d => %08x\n", pc, memory[op1].iV, memory[op2].iV, pc+((int)jumpPosition-6));
                    sys_puts_serial(debugBuffer);
                #endif
				if((memory[op1].iV) >= (memory[op2].iV))
					pc += ((int)jumpPosition-6);
				break;
			case OP_SWITCH:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x SWITCH = %d\n", pc, memory[op1].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				index = pc+6+((memory[op1].iV)*2);
				pc += ((short)((program[index]&0xFF) + (program[index+1]<<8)));
				break;
			case OP_JUMP:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x JUMP => %08x\n", pc, pc+((int)jumpPosition-6));
                    sys_puts_serial(debugBuffer);
                #endif
				pc += ((int)jumpPosition-6);
				break;
			case OP_RETURN:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x RETURN\n", pc);
                    sys_puts_serial(debugBuffer);
                #endif
				return (MEM_SLOT)0;
			case OP_RETURNV:
                MEM_SLOT retval = memory[op1];
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x RETURNV => %p\n", pc, retval.pV);
                    sys_puts_serial(debugBuffer);
                #endif
				return retval;
			case OP_ALLOC8:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x ALLOC8 @ %d\n", pc, memory[op1].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				//memory[stackslot].pV = alloca(memory[op1].iV * sizeof(char));

                // do this instead to now rely on alloca/malloc
                unsigned int sizeA8 = memory[op1].iV * sizeof(char);
                memory[stackslot].pV = &allocationBuffer[allocationBufferIndex];
                allocationBufferIndex += sizeA8;
                if(allocationBufferIndex > ALLOCATION_BUFFER_SIZE) {
                    #ifdef DEBUG2
                        snprintf(debugBuffer, sizeof(debugBuffer), "ERROR: OUT OF MEMORY\n");
                        sys_puts_serial(debugBuffer);
                    #endif
                    return (MEM_SLOT)0;
                }
                
				break;
			case OP_ALLOC16:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x ALLOC16 @ %d\n", pc, memory[op1].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				//memory[stackslot].pV = alloca(memory[op1].iV * sizeof(short));
                
                // do this instead to now rely on alloca/malloc
                unsigned int sizeA16 = memory[op1].iV * sizeof(short);
                memory[stackslot].pV = &allocationBuffer[allocationBufferIndex];
                allocationBufferIndex += sizeA16;
                if(allocationBufferIndex > ALLOCATION_BUFFER_SIZE) {
                    #ifdef DEBUG2
                        snprintf(debugBuffer, sizeof(debugBuffer), "ERROR: OUT OF MEMORY\n");
                        sys_puts_serial(debugBuffer);
                    #endif
                    return (MEM_SLOT)0;
                }
                
				break;
			case OP_ALLOC32:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x ALLOC32 @ %d\n", pc, memory[op1].iV);
                    sys_puts_serial(debugBuffer);
                #endif
				//memory[stackslot].pV = alloca(memory[op1].iV * sizeof(int));
                
                // do this instead to now rely on alloca/malloc
                unsigned int sizeA32 = memory[op1].iV * sizeof(int);
                memory[stackslot].pV = &allocationBuffer[allocationBufferIndex];
                allocationBufferIndex += sizeA32;
                if(allocationBufferIndex > ALLOCATION_BUFFER_SIZE) {
                    #ifdef DEBUG2
                        snprintf(debugBuffer, sizeof(debugBuffer), "ERROR: OUT OF MEMORY\n");
                        sys_puts_serial(debugBuffer);
                    #endif
                    return (MEM_SLOT)0;
                }
                
				break;
			case OP_ALLOCP:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x ALLOCP @ %d\n", pc, memory[op1].iV);
                #endif
				//memory[stackslot].pV = alloca(memory[op1].iV * sizeof(void*));
                
                // do this instead to now rely on alloca/malloc
                unsigned int sizeAP = memory[op1].iV * sizeof(void*);
                memory[stackslot].pV = &allocationBuffer[allocationBufferIndex];
                allocationBufferIndex += sizeAP;
                if(allocationBufferIndex > ALLOCATION_BUFFER_SIZE) {
                    #ifdef DEBUG2
                        snprintf(debugBuffer, sizeof(debugBuffer), "ERROR: OUT OF MEMORY\n");
                        sys_puts_serial(debugBuffer);
                    #endif
                    return (MEM_SLOT)0;
                }
				break;
			case OP_OCONST:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]OCONST = appendedData[%d]\n", pc, stackslot, data);
                    sys_puts_serial(debugBuffer);
                #endif
				memory[stackslot].pV = appendedData[data].pV;
				break;
            case OP_CUSTOM_PREPCALL:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]CUSTOM_PREPCALL = {%p %p %p %p}\n", pc, stackslot, memory[op1].pV, memory[op2].pV, memory[op3].pV, memory[op4].pV);
                    sys_puts_serial(debugBuffer);
                #endif
                MEM_SLOT bufferPrepcall[4];
                bufferPrepcall[0].pV = memory[op1].pV;
                bufferPrepcall[1].pV = memory[op2].pV;
                bufferPrepcall[2].pV = memory[op3].pV;
                bufferPrepcall[3].pV = memory[op4].pV;
                memory[stackslot].pV = bufferPrepcall;
                break;
            case OP_CUSTOM_CALL:
                #ifdef DEBUG
                    snprintf(debugBuffer, sizeof(debugBuffer), "%08x [%d]CUSTOM_CALL = %p @ %d\n", pc, stackslot, memory[op1].pV, op1);
                    sys_puts_serial(debugBuffer);
                #endif
                memory[stackslot] = vm(program, appendedData, (MEM_SLOT*)memory[op1].pV);
                break;
			default:
                #ifdef DEBUG2
                snprintf(debugBuffer, sizeof(debugBuffer), "ERROR: Illegal Opcode %02X @ %08x\n", opcode, pc);
                sys_puts_serial(debugBuffer);
                #endif
				return (MEM_SLOT)0;
			}
			
			pc += 6;
			
		}
}