#ifndef PXE_H
#define PXE_H

#pragma pack(push,1)

// PXE structures and definitions from specs
// and in reference to https://github.com/ipxe/ipxe/blob/master/src/arch/x86/include/pxe_api.h

#define ID_PXENV_FILE_OPEN        0x00e0
#define ID_PXENV_FILE_CLOSE       0x00e1
#define ID_PXENV_FILE_READ        0x00e3
#define ID_PXENV_FILE_API_CHECK   0x00e6

struct s_SEGOFF16 {
    uint16_t offset;
    uint16_t segment;
} __attribute__((packed));

struct s_SEGDESC {
    uint16_t    segment_address; 
    uint32_t    Physical_address;
    uint16_t    Seg_size; 
} __attribute__((packed)) ;

typedef struct s_SEGOFF16 SEGOFF16;
typedef struct s_SEGDESC  SEGDESC;

struct s_PXE {
    uint8_t     Signature[4];
    uint8_t     StructLength;
    uint8_t     StructCksum;
    uint8_t     StructRev;
    uint8_t     reserved0;
    SEGOFF16    UNDIROMID;
    SEGOFF16    BaseROMID;
    SEGOFF16    EntryPointSP;
    SEGOFF16    EntryPointESP;
    SEGOFF16    StatusCallout;
    uint8_t     reserved1;
    uint8_t     SegDescCnt;
    uint16_t    FirstSelector;
    SEGDESC     Stack;
    SEGDESC     UNDIData;
    SEGDESC     UNDICode;
    SEGDESC     UNDICodeWrite;
    SEGDESC     BC_Data;
    SEGDESC     BC_Code;
    SEGDESC     BC_CodeWrite;
} __attribute__((packed));


struct s_PXENV {
    uint8_t     Signature[6];
    uint16_t    Version;
    uint8_t     Length;
    uint8_t     Checksum;
    SEGOFF16    RMEntry;
    uint32_t    PMOffset;
    uint16_t    PMSelector;
    uint16_t    StackSeg;
    uint16_t    StackSize;
    uint16_t    BC_CodeSeg;
    uint16_t    BC_CodeSize;
    uint16_t    BC_DataSeg;
    uint16_t    BC_DataSize;
    uint16_t    UNDIDataSeg;
    uint16_t    UNDIDataSize;
    uint16_t    UNDICodeSeg;
    uint16_t    UNDICodeSize;
    SEGOFF16    PXEPtr;
} __attribute__((packed));


struct s_PXENV_FILE_OPEN {
    uint16_t Status;
    uint16_t FileHandle;
    SEGOFF16 FileName;
    uint32_t Reserved;
} __attribute__((packed));

struct s_PXENV_FILE_CLOSE {
    uint16_t Status;
    uint16_t FileHandle;
} __attribute__((packed));

struct s_PXENV_FILE_READ {
    uint16_t Status;
    uint16_t FileHandle;
    uint16_t BufferSize;
    SEGOFF16 Buffer;
} __attribute__((packed));

struct s_PXENV_FILE_API_CHECK {
    uint16_t Status;
    uint16_t Size;
    uint32_t Magic;
    uint32_t Provider;
    uint32_t APIMask;
    uint32_t Flags;
} __attribute__((packed));


typedef struct s_PXE PXE;
typedef struct s_PXENV PXENV;

typedef struct s_PXENV_FILE_OPEN         PXENV_FILE_OPEN;
typedef struct s_PXENV_FILE_CLOSE        PXENV_FILE_CLOSE;
typedef struct s_PXENV_FILE_READ         PXENV_FILE_READ;
typedef struct s_PXENV_FILE_API_CHECK    PXENV_FILE_API_CHECK;

#pragma pack(pop)
#endif