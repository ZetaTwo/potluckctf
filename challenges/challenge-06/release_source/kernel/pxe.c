#include <stdint.h>
#include "pxe.h"
#include "kernel.h"
#include "helper.h"


// C Definition of the PXEAPI defined in the netboot file
extern int PXEAPI(SEGOFF16 PXEAPIEntryPont, SEGOFF16 DataPointer, uint32_t OpCode);

// A buffer within 16-bit addressable range for receiving blocks of a file
volatile uint8_t* BUFFER = (volatile uint8_t*)0x500; // 0x00000500     0x00007BFF     almost 30 KiB     Conventional memory 

// The PXE API Entry Point which is required for all PXE Calls
SEGOFF16 PXEAPIEntryPont;



// Convert Flat Memory Address to Segment and Offset Structure
SEGOFF16 toSEGOFF16(volatile void* addr) {
    SEGOFF16 so;
    so.segment = (uint16_t)((((uint32_t)addr)&0xFFFF0)>>4);
    so.offset  = (uint16_t)(((uint32_t)addr)&0xF);
    return so;
}

// Convert Segment and Offset Structure to Flat Memory Address
void* fromSEGOFF16(volatile SEGOFF16 so) {
    return (void*)((((uint32_t)so.segment&0xFFFF)<<4) + ((uint32_t)so.offset&0xFFFF));
}

// Verify the correctness of the PXEnv+ Structure
uint8_t verifyPXENV(PXENV* s) {

    // Check the Signature
    if(*((uint32_t*)&s->Signature[0]) != 0x4E455850) return 0;
    if(*((uint16_t*)&s->Signature[4]) != 0x2B56) return 0;

    uint8_t lenght = s->Length;
    
    // Check for length
    if(lenght < 0x28) return 0;
    
    // Verify Checksum is equal to 0
    uint8_t checksum = 0;
    for(int i=0;i<lenght;i++)
        checksum = checksum + ((uint8_t*)s)[i];

    return checksum == 0;
}

// Verify the correctness of the !PXE Structure
uint8_t verifyPXE(PXE* s) {
 
    // Check the Signature
    if(*((uint32_t*)&s->Signature[0]) != 0x45585021) return 0;
   
    uint8_t lenght = s->StructLength;
    
    // Check for length
    if(lenght < 0x58) return 0;
    
    // Verify Checksum is equal to 0
    uint8_t checksum = 0;
    for(int i=0;i<lenght;i++)
        checksum = checksum + ((uint8_t*)s)[i];

    return checksum == 0;
}


uint32_t readFilePXE(SEGOFF16 PXEAPIEntryPont, char* filePath, uint8_t* dest, uint32_t maxSize) {
    PXENV_FILE_OPEN fo = {0};
    PXENV_FILE_CLOSE fc = {0};
    PXENV_FILE_READ fr = {0};
    
    fo.Reserved = 0;
    
    // fixed url
    strcpy(BUFFER, filePath);
    fo.FileName = toSEGOFF16(BUFFER);

    // Request the File from the Server
    int exitCode = 0;
    if((exitCode=PXEAPI(PXEAPIEntryPont, toSEGOFF16(&fo), ID_PXENV_FILE_OPEN)))
        exit("@ Opening File", exitCode);
    
    // Opening the file returns a file handle
    fc.FileHandle = fo.FileHandle;


    uint32_t amount = 0; 
    
    do {
        fr.FileHandle = fo.FileHandle; 
        // Block Size
        fr.BufferSize = 0x200;
        // Reuse our BUFFER for receiving the data
        fr.Buffer = toSEGOFF16(BUFFER);
        
        // Read a block of data using the API 
        while((exitCode=PXEAPI(PXEAPIEntryPont, toSEGOFF16(&fr), ID_PXENV_FILE_READ))) {
            if(exitCode == 0x1B) {
                // we just wait here
            }else
                exit("@ Reading File", exitCode);
        }
        
        // Copy the data from the receive buffer into the destination buffer
        for(int i=0;i<fr.BufferSize;i++)
            dest[amount+i] =  BUFFER[i];
        
        amount += fr.BufferSize;
    
    }while(fr.BufferSize != 0 && amount<maxSize);
        
    // Close the connection
    if((exitCode=PXEAPI(PXEAPIEntryPont, toSEGOFF16(&fc), ID_PXENV_FILE_CLOSE)))
        exit("@ Closing File", exitCode);
        
    return amount;
}

uint32_t readFile(char* filePath, uint8_t* dest, uint32_t maxSize) {
    return readFilePXE(PXEAPIEntryPont, filePath, dest, maxSize);
}


void initPXE(SEGOFF16 pxe) {
    // Convert SEGOFF to actual pointer
    PXENV* PXEEnvPtr = fromSEGOFF16(pxe);
    
    // Verify Integrity of PXEEnv+ Structure
    if(!verifyPXENV(PXEEnvPtr))
        exit("@ Verifying PXENV+", 0xFF);
        
    // The !PXE Struct was introduced in PXE 2.1, if the systems version is lower then another api entrypoint has to be used
    if(PXEEnvPtr->Version < 0x0201) { 
        // Realmode PXEnv+ API Entrypoint
        PXEAPIEntryPont = PXEEnvPtr->RMEntry;
    }else {
        PXE* PXEPtr = fromSEGOFF16(PXEEnvPtr->PXEPtr);
        
         // Verify Integrity of !PXE Structure
        if(!verifyPXE(PXEPtr))
            exit("@ Verifying !PXE", 0xFF);
        
        // Realmode !PXE API Entrypoint
        PXEAPIEntryPont = PXEPtr->EntryPointSP; 
    }
    
    
    // Do an API Check for the fancy feature we want to use
    // See https://github.com/TritonDataCenter/syslinux/blob/master/core/fs/pxe/pxe.c
    PXENV_FILE_API_CHECK s_apiCheck = {0};
    s_apiCheck.Size  = sizeof(s_apiCheck);
    s_apiCheck.Magic = 0x91d447b2;
    
    int exitCode = 0;
    if((exitCode=PXEAPI(PXEAPIEntryPont, toSEGOFF16(&s_apiCheck), ID_PXENV_FILE_API_CHECK)))
        exit("@ API Check", exitCode);
    
    // Check if gPXE/iPXE is found
    if(s_apiCheck.Magic != 0xe9c17b20)
        exit("@ No gPXE/iPXE", s_apiCheck.Provider);
    
    // Check if File API is available
    if((~s_apiCheck.APIMask & 0x4b) != 0)
        exit("@ API Functions not supported", s_apiCheck.APIMask);
    
 
}