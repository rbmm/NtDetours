////////////////////////////////////////////////////////////////////////////////
//
//  Microsoft Research Singularity
//
//  Copyright (c) Microsoft Corporation.  All rights reserved.
//
//  File:   Dump.h
//
//  Note:   Constants and types for kernel dump files.
//

#pragma warning(push)
#pragma warning(disable : 4200) // don't warn about zero-sized array in struct/union

#ifdef __cplusplus
extern "C" {
#endif

#define USERMODE_CRASHDUMP_SIGNATURE    'RESU'
#define USERMODE_CRASHDUMP_VALID_DUMP32 'PMUD'
#define USERMODE_CRASHDUMP_VALID_DUMP64 '46UD'

typedef struct _USERMODE_CRASHDUMP_HEADER64 {
    ULONG       Signature;
    ULONG       ValidDump;
    ULONG       MajorVersion;
    ULONG       MinorVersion;
    ULONG       MachineImageType;
    ULONG       ThreadCount;
    ULONG       ModuleCount;
    ULONG       MemoryRegionCount;
    ULONGLONG   ThreadOffset;
    ULONGLONG   ModuleOffset;
    ULONGLONG   DataOffset;
    ULONGLONG   MemoryRegionOffset;
    ULONGLONG   DebugEventOffset;
    ULONGLONG   ThreadStateOffset;
    ULONGLONG   VersionInfoOffset;
    ULONGLONG   Spare1;
} USERMODE_CRASHDUMP_HEADER64, *PUSERMODE_CRASHDUMP_HEADER64;

typedef struct _CRASH_MODULE64 {
    ULONGLONG   BaseOfImage;
    ULONG       SizeOfImage;
    ULONG       ImageNameLength;
    CHAR        ImageName[0];
} CRASH_MODULE64, *PCRASH_MODULE64;

typedef struct _CRASH_THREAD64 {
    ULONG       ThreadId;
    ULONG       SuspendCount;
    ULONG       PriorityClass;
    ULONG       Priority;
    ULONGLONG   Teb;
    ULONGLONG   Spare0;
    ULONGLONG   Spare1;
    ULONGLONG   Spare2;
    ULONGLONG   Spare3;
    ULONGLONG   Spare4;
    ULONGLONG   Spare5;
    ULONGLONG   Spare6;
} CRASH_THREAD64, *PCRASH_THREAD64;

typedef struct _CRASHDUMP_VERSION_INFO {
    int     IgnoreGuardPages;       // Whether we should ignore GuardPages or not
    ULONG   PointerSize;            // 32, 64 bit pointers
} CRASHDUMP_VERSION_INFO, *PCRASHDUMP_VERSION_INFO;

//
// usermode crash dump data types
//
#define DMP_EXCEPTION                 1 // obsolete
#define DMP_MEMORY_BASIC_INFORMATION  2
#define DMP_THREAD_CONTEXT            3
#define DMP_MODULE                    4
#define DMP_MEMORY_DATA               5
#define DMP_DEBUG_EVENT               6
#define DMP_THREAD_STATE              7
#define DMP_DUMP_FILE_HANDLE          8

//
// Define the information required to process memory dumps.
//


typedef enum _DUMP_TYPES {
    DUMP_TYPE_INVALID           = -1,
    DUMP_TYPE_UNKNOWN           = 0,
    DUMP_TYPE_FULL              = 1,
    DUMP_TYPE_SUMMARY           = 2,
    DUMP_TYPE_HEADER            = 3,
    DUMP_TYPE_TRIAGE            = 4,
	DUMP_TYPE_BITMAP_FULL		= 5,
	DUMP_TYPE_BITMAP_KERNEL		= 6,
} DUMP_TYPE;


//
// Signature and Valid fields.
//

#define DUMP_SIGNATURE   ('EGAP')

#define DUMP_VALID_DUMP32  ('PMUD')

#define DUMP_VALID_DUMP64  ('46UD')

#define FULL_SUMMARY_SIGNATURE  ('PMDF')
#define DUMP_SUMMARY_SIGNATURE  ('PMDS')
#define DUMP_SUMMARY_VALID      ('PMUD')

#define DUMP_SUMMARY_VALID_KERNEL_VA                     (1)
#define DUMP_SUMMARY_VALID_CURRENT_USER_VA               (2)

//
//
// NOTE: The definition of PHYISCAL_MEMORY_RUN and PHYSICAL_MEMORY_DESCRIPTOR
// MUST be the same as in mm.h. The kernel portion of crashdump will
// verify that these structs are the same.
//

typedef struct PHYSICAL_MEMORY_RUN32 {
	ULONG BasePage;
	ULONG PageCount;
} *PPHYSICAL_MEMORY_RUN32;

typedef struct PHYSICAL_MEMORY_RUN64 {
    ULONG64 BasePage;
    ULONG64 PageCount;
} *PPHYSICAL_MEMORY_RUN64;

typedef struct PHYSICAL_MEMORY_DESCRIPTOR32 {
	ULONG NumberOfRuns;
	ULONG NumberOfPages;
	PHYSICAL_MEMORY_RUN32 Run[];
} *PPHYSICAL_MEMORY_DESCRIPTOR32;


typedef struct PHYSICAL_MEMORY_DESCRIPTOR64 {
    ULONG NumberOfRuns;
    ULONG64 NumberOfPages;
    PHYSICAL_MEMORY_RUN64 Run[];
} *PPHYSICAL_MEMORY_DESCRIPTOR64;


typedef struct _UNLOADED_DRIVERS64 {
    UNICODE_STRING64 Name;
    ULONG64 StartAddress;
    ULONG64 EndAddress;
    LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVERS64, *PUNLOADED_DRIVERS64;

#define MAX_UNLOADED_NAME_LENGTH 24

typedef struct _DUMP_UNLOADED_DRIVERS64
{
    UNICODE_STRING64 Name;
    WCHAR DriverName[MAX_UNLOADED_NAME_LENGTH / sizeof (WCHAR)];
    ULONG64 StartAddress;
    ULONG64 EndAddress;
} DUMP_UNLOADED_DRIVERS64, *PDUMP_UNLOADED_DRIVERS64;

typedef struct _DUMP_MM_STORAGE64
{
    ULONG Version;
    ULONG Size;
    ULONG MmSpecialPoolTag;
    ULONG MiTriageActionTaken;

    ULONG MmVerifyDriverLevel;
    ULONG KernelVerifier;
    ULONG64 MmMaximumNonPagedPool;
    ULONG64 MmAllocatedNonPagedPool;

    ULONG64 PagedPoolMaximum;
    ULONG64 PagedPoolAllocated;

    ULONG64 CommittedPages;
    ULONG64 CommittedPagesPeak;
    ULONG64 CommitLimitMaximum;
} DUMP_MM_STORAGE64, *PDUMP_MM_STORAGE64;


//
// Define the dump header structure. You cannot change these
// defines without breaking the debuggers, so don't.
//

#define DMP_PHYSICAL_MEMORY_BLOCK_SIZE      (700)

#define DMP_CONTEXT_RECORD_SIZE_32          (1200)
#define DMP_RESERVED_0_SIZE_32              (1764)
#define DMP_RESERVED_2_SIZE_32              (16)
#define DMP_RESERVED_3_SIZE_32              (56)

#define DMP_CONTEXT_RECORD_SIZE_64          (3000)
#define DMP_RESERVED_0_SIZE_64              (4012)

#define DMP_HEADER_COMMENT_SIZE             (128)

// Unset WriterStatus value from the header fill.
#define DUMP_WRITER_STATUS_UNINITIALIZED    DUMP_SIGNATURE

// WriterStatus codes for the dbgeng.dll dump writers.
enum
{
    DUMP_DBGENG_SUCCESS,
    DUMP_DBGENG_NO_MODULE_LIST,
    DUMP_DBGENG_CORRUPT_MODULE_LIST,
};

struct DUMP_HEADER {
	/*0000*/ULONG Signature;
	/*0004*/ULONG ValidDump;
	/*0008*/ULONG Version;
	/*000c*/ULONG dwBuildNumber;
};

typedef struct DUMP_HEADER32 : DUMP_HEADER {
	/*0010*/ULONG DirectoryTableBase;
	/*0014*/ULONG PfnDataBase;
	/*0018*/ULONG PsLoadedModuleList;
	/*001c*/ULONG PsActiveProcessHead;
	/*0020*/ULONG MachineImageType;
	/*0024*/ULONG NumberProcessors;
	/*0028*/ULONG BugCheckCode;
	/*002c*/ULONG BugCheckParameter[4];
	/*003c*/CHAR VersionUser[32];
	/*005c*/UCHAR PaeEnabled;
	/*005d*/UCHAR KdSecondaryVersion;       // Present only for W2K3 SP1 and better
	/*005e*/UCHAR Unused[2];
	/*0060*/ULONG KdDebuggerDataBlock;

	/*0064*/ULONG NumberOfRuns;
	/*0068*/ULONG NumberOfPages;
	/*006c*/PHYSICAL_MEMORY_RUN32 Run[0x56];
	/*031c*/ULONG pad;

	/*0320*/UCHAR ContextRecord [ DMP_CONTEXT_RECORD_SIZE_32 ];
	/*07d0*/EXCEPTION_RECORD32 Exception;
	/*0820*/CHAR Comment [ DMP_HEADER_COMMENT_SIZE ];   // May not be present.
	/*08a0*/ULONG Attributes; // optional
	/*08a4*/UCHAR _reserved0[ DMP_RESERVED_0_SIZE_32 ];
	/*0f88*/DUMP_TYPE DumpType;
	/*0f8c*/LONG  MiniDumpFields;
	/*0f90*/ULONG SecondaryDataState;
	/*0f94*/ULONG ProductType;
	/*0f98*/ULONG SuiteMask;
	/*0f9c*/ULONG WriterStatus;
	/*0fa0*/LARGE_INTEGER RequiredDumpSpace; //  A2B0B05
	/*0fa8*/UCHAR Unused2[DMP_RESERVED_2_SIZE_32];
	/*0fb8*/LARGE_INTEGER SystemUpTime;
	/*0fc0*/LARGE_INTEGER SystemTime;
	/*0fc8*/UCHAR Unused3[DMP_RESERVED_3_SIZE_32];
} *PDUMP_HEADER32;

typedef struct DUMP_HEADER64 : DUMP_HEADER {
	/*0010*/ULONG64 DirectoryTableBase;
	/*0018*/ULONG64 PfnDataBase;
	/*0020*/ULONG64 PsLoadedModuleList;
	/*0028*/ULONG64 PsActiveProcessHead;
	/*0030*/ULONG MachineImageType;
	/*0034*/ULONG NumberProcessors;
	/*0038*/ULONG BugCheckCode;
	/*0040*/ULONG64 BugCheckParameter[4];
	/*0060*/CHAR VersionUser[32];
	/*0080*/ULONG64 KdDebuggerDataBlock;

	/*0088*/ULONG NumberOfRuns;
	/*0090*/ULONG64 NumberOfPages;
	/*0098*/PHYSICAL_MEMORY_RUN64 Run[0x2b];

	/*0348*/UCHAR ContextRecord [ DMP_CONTEXT_RECORD_SIZE_64 ];
	/*0f00*/EXCEPTION_RECORD64 Exception;
	/*0f98*/DUMP_TYPE DumpType;
	/*0fa0*/LARGE_INTEGER RequiredDumpSpace;
	/*0fa8*/LARGE_INTEGER SystemTime;
	/*0fb0*/CHAR Comment [ DMP_HEADER_COMMENT_SIZE ];   // May not be present.
	/*1030*/LARGE_INTEGER SystemUpTime;
	/*1038*/LONG  MiniDumpFields;
	/*103c*/ULONG SecondaryDataState;
	/*1040*/ULONG ProductType;
	/*1044*/ULONG SuiteMask;
	/*1048*/ULONG WriterStatus;
	/*104c*/UCHAR Unused1;
	/*104d*/UCHAR KdSecondaryVersion;       // Present only for W2K3 SP1 and better
	/*104e*/UCHAR Unused[2];
	/*1050*/ULONG Attributes;
	/*1054*/UCHAR _reserved0[ DMP_RESERVED_0_SIZE_64 ];
	/*2000*/
} *PDUMP_HEADER64;

typedef struct FULL_DUMP {
    CHAR Memory[];             // Variable length to the end of the dump file.
} *PFULL_DUMP;


struct COMMON_BITMAP_DUMP
{
	ULONG	Signature; //DUMP_SUMMARY_SIGNATURE
	ULONG	ValidDump; //DUMP_SUMMARY_VALID
	ULONG	BitsOffset;
	ULONG	WaitSignature;
	ULONG64 HeaderSize; // Offset to the start of actual memory dump
	ULONG64 Pages;
	ULONG64 BitmapSize; // Total bitmap size (i.e., maximum #bits)
	ULONG64 RequiredDumpSpace;
};

typedef struct BITMAP_DUMP { // n = 1 for 32 and 2 for 64 dump
	/*n000*/    ULONG Signature; //DUMP_SUMMARY_SIGNATURE
	/*n004*/    ULONG ValidDump; //DUMP_SUMMARY_VALID
	/*n008*/    ULONG DumpOptions;  // Summary Dump Options
	/*n00c*/    UCHAR unused[20];
	/*n020*/    ULONG64 HeaderSize; // Offset to the start of actual memory dump
	/*n028*/    ULONG64 Pages;
	/*n030*/    ULONG64 BitmapSize; // Total bitmap size (i.e., maximum #bits)
	/*n038*/    UCHAR Bits[];
} * PBITMAP_DUMP;

//
// ISSUE - 2000/02/17 - math: NT64 Summary dump.
//
// This is broken. The 64 bit summary dump should have a ULONG64 for
// the BitmapSize to match the size of the PFN_NUMBER.
//

struct SUMMARY_DUMP32 {
    /*1000*/ULONG Signature;
    /*1004*/ULONG ValidDump;
    /*1008*/ULONG DumpOptions;  // Summary Dump Options
    /*100c*/ULONG HeaderSize;   // Offset to the start of actual memory dump
    /*1010*/ULONG BitmapSize;   // Total bitmap size (i.e., maximum #bits)
    /*1014*/ULONG Pages;        // Total bits set in bitmap (i.e., total pages in sdump)

    //
    // ISSUE - 2000/02/17 - math: Win64
    //
    // With a 64-bit PFN, we should not have a 32-bit bitmap.
    //

    //
    // These next three fields essentially form an on-disk RTL_BITMAP structure.
    // The RESERVED field is stupidness introduced by the way the data is
    // serialized to disk.
    //

    /*1018*/ULONG SizeOfBitMap;
    /*101c*/ULONG _reserved0;
    /*1020*/UCHAR Bits[];

} * PSUMMARY_DUMP32;

struct SUMMARY_DUMP64 {
	/*2000*/ULONG Signature;
	/*2004*/ULONG ValidDump;
	/*2008*/ULONG DumpOptions;  // Summary Dump Options
	/*200c*/ULONG HeaderSize;   // Offset to the start of actual memory dump
	/*2010*/ULONG BitmapSize;   // Total bitmap size (i.e., maximum #bits)
	/*2014*/ULONG Pages;        // Total bits set in bitmap (i.e., total pages in sdump)

	//
	// ISSUE - 2000/02/17 - math: Win64
	//
	// With a 64-bit PFN, we should not have a 32-bit bitmap.
	//

	//
	// These next three fields essentially form an on-disk RTL_BITMAP structure.
	// The RESERVED field is stupidness introduced by the way the data is
	// serialized to disk.
	//

	/*2018*/ULONG SizeOfBitMap;
	/*2020*/ULONG64 _reserved0;
	/*2028*/UCHAR Bits[];

} * PSUMMARY_DUMP64;


typedef struct TRIAGE_DUMP32 {
	/*0000*/ULONG ServicePackBuild;             // What service pack of NT was this ?
	/*0004*/ULONG SizeOfDump;                   // Size in bytes of the dump
	/*0008*/ULONG ValidOffset;                  // Offset to `DGRT`
	/*000c*/ULONG ContextOffset;                // Offset of CONTEXT record
	/*0010*/ULONG ExceptionOffset;              // Offset of EXCEPTION record
	/*0014*/ULONG MmOffset;                     // Offset of Mm information
	/*0018*/ULONG UnloadedDriversOffset;        // Offset of Unloaded Drivers
	/*001c*/ULONG PrcbOffset;                   // Offset of KPRCB
	/*0020*/ULONG ProcessOffset;                // Offset of EPROCESS
	/*0024*/ULONG ThreadOffset;                 // Offset of ETHREAD
	/*0028*/ULONG CallStackOffset;              // Offset of CallStack Pages
	/*002c*/ULONG SizeOfCallStack;              // Size in bytes of CallStack
	/*0030*/ULONG DriverListOffset;             // Offset of Driver List
	/*0034*/ULONG DriverCount;                  // Number of Drivers in list
	/*0038*/ULONG StringPoolOffset;             // Offset to the string pool
	/*003c*/ULONG StringPoolSize;               // Size of the string pool
	/*0040*/ULONG BrokenDriverOffset;           // Offset into the driver of the driver that crashed
	/*0044*/ULONG TriageOptions;                // Triage options in effect at crashtime
	/*0048*/ULONG TopOfStack;                 // The top (highest address) of the callstack
	/*004c*/ULONG DataPageAddress;
	/*0050*/ULONG DataPageOffset;
	/*0054*/ULONG DataPageSize;
	/*0058*/ULONG DebuggerDataOffset;
	/*005c*/ULONG DebuggerDataSize;
	/*0060*/ULONG DataBlocksOffset;
	/*0064*/ULONG DataBlocksCount;

} *PTRIAGE_DUMP32;

typedef struct TRIAGE_DUMP64 {
    /*0000*/ULONG ServicePackBuild;             // What service pack of NT was this ?
    /*0004*/ULONG SizeOfDump;                   // Size in bytes of the dump
    /*0008*/ULONG ValidOffset;                  // Offset to `DGRT`
    /*000c*/ULONG ContextOffset;                // Offset of CONTEXT record
    /*0010*/ULONG ExceptionOffset;              // Offset of EXCEPTION record
    /*0014*/ULONG MmOffset;                     // Offset of Mm information
    /*0018*/ULONG UnloadedDriversOffset;        // Offset of Unloaded Drivers
    /*001c*/ULONG PrcbOffset;                   // Offset of KPRCB
    /*0020*/ULONG ProcessOffset;                // Offset of EPROCESS
    /*0024*/ULONG ThreadOffset;                 // Offset of ETHREAD
    /*0028*/ULONG CallStackOffset;              // Offset of CallStack Pages
    /*002c*/ULONG SizeOfCallStack;              // Size in bytes of CallStack
    /*0030*/ULONG DriverListOffset;             // Offset of Driver List
    /*0034*/ULONG DriverCount;                  // Number of Drivers in list
    /*0038*/ULONG StringPoolOffset;             // Offset to the string pool
    /*003c*/ULONG StringPoolSize;               // Size of the string pool
    /*0040*/ULONG BrokenDriverOffset;           // Offset into the driver of the driver that crashed
    /*0044*/ULONG TriageOptions;                // Triage options in effect at crashtime
    /*0048*/ULONG64 TopOfStack;                 // The top (highest address) of the callstack

    //
    // Architecture Specific fields.
    //

    union {

        //
        // For IA64 we need to store the BStore as well.
        //

        struct {
            /**0050*/ULONG BStoreOffset;         // Offset of BStore region.
            /*0054*/ULONG SizeOfBStore;         // The size of the BStore region.
            /*0058*/ULONG64 LimitOfBStore;      // The limit (highest memory address)
        } Ia64;                         //  of the BStore region.

    } ArchitectureSpecific;

    /*0060*/ULONG64 DataPageAddress;
    /*0068*/ULONG   DataPageOffset;
    /*006c*/ULONG   DataPageSize;

    /*0070*/ULONG   DebuggerDataOffset;
    /*0074*/ULONG   DebuggerDataSize;

    /*0078*/ULONG   DataBlocksOffset;
    /*007c*/ULONG   DataBlocksCount;

} * PTRIAGE_DUMP64;


typedef struct MEMORY_DUMP64 : DUMP_HEADER64 {
    union {
        FULL_DUMP Full;               // DumpType == DUMP_TYPE_FULL
        TRIAGE_DUMP64 Triage;           // DumpType == DUMP_TYPE_TRIAGE
        SUMMARY_DUMP64 Summary;         // DumpType == DUMP_TYPE_SUMMARY
		BITMAP_DUMP Bitmap;			// DumpType == DUMP_TYPE_BITMAP_*
		UCHAR SpecificDump[];
    };

} *PMEMORY_DUMP64;

typedef struct MEMORY_DUMP32 : DUMP_HEADER32 {
	union {
		FULL_DUMP Full;               // DumpType == DUMP_TYPE_FULL
		TRIAGE_DUMP32 Triage;           // DumpType == DUMP_TYPE_TRIAGE
		SUMMARY_DUMP32 Summary;         // DumpType == DUMP_TYPE_SUMMARY
		BITMAP_DUMP Bitmap;			// DumpType == DUMP_TYPE_BITMAP_*
		UCHAR SpecificDump[];
	};

} *PMEMORY_DUMP32;

typedef struct _TRIAGE_DATA_BLOCK {
    ULONG64 Address;
    ULONG Offset;
    ULONG Size;
} TRIAGE_DATA_BLOCK, *PTRIAGE_DATA_BLOCK;

//
// In the triage dump ValidFields field what portions of the triage-dump have
// been turned on.
//

#define TRIAGE_DUMP_CONTEXT          (0x0001)
#define TRIAGE_DUMP_EXCEPTION        (0x0002)
#define TRIAGE_DUMP_PRCB             (0x0004)
#define TRIAGE_DUMP_PROCESS          (0x0008)
#define TRIAGE_DUMP_THREAD           (0x0010)
#define TRIAGE_DUMP_STACK            (0x0020)
#define TRIAGE_DUMP_DRIVER_LIST      (0x0040)
#define TRIAGE_DUMP_BROKEN_DRIVER    (0x0080)
#define TRIAGE_DUMP_BASIC_INFO       (0x00FF)
#define TRIAGE_DUMP_MMINFO           (0x0100)
#define TRIAGE_DUMP_DATAPAGE         (0x0200)
#define TRIAGE_DUMP_DEBUGGER_DATA    (0x0400)
#define TRIAGE_DUMP_DATA_BLOCKS      (0x0800)

#define TRIAGE_OPTION_OVERFLOWED     (0x0100)

#define TRIAGE_DUMP_VALID       ( 'DGRT' )
#define TRIAGE_DUMP_SIZE32      ( 0x1000 * 16 )
#define TRIAGE_DUMP_SIZE64      ( 0x2000 * 16 )

//
// The DUMP_STRING is guaranteed to be both NULL terminated and length prefixed
// (prefix does not include the NULL).
//

typedef struct _DUMP_STRING {
    ULONG Length;                   // Length IN BYTES of the string.
    WCHAR Buffer [0];               // Buffer.
} DUMP_STRING, * PDUMP_STRING;

struct BLOBDUMP {
	union {
		CHAR DumpBlob[8];
		struct {
			ULONG Dump;
			ULONG Blob;
		};
	};
	ULONG cbHeader;
	ULONG Unknown;
};

struct TAGBLOBHEADER
{
	ULONG cbHeader;
	GUID tag;
	ULONG cbData;
	ULONG cbData1;
	ULONG cbData2;
};

#ifdef __cplusplus
}
#endif

#pragma warning(pop)