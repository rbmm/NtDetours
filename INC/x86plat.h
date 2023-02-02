#pragma once

#pragma pack(push,1)

typedef struct SEGMENT_ENTRY
{
	unsigned	Limit0		:	16;
	unsigned	Base0		:	16;
	unsigned	Base1		:	 8;
	unsigned	Type		:	 4;
	unsigned	IsGegment	:	 1;
	unsigned	DPL			:	 2;
	unsigned	P			:	 1;
	unsigned	Limit1		:	 4;
	unsigned	AVL			:	 1;
	unsigned	Reserv		:	 1;
	unsigned	D			:	 1;
	unsigned	G			:	 1;
	unsigned	Base2		:	 8;
}*PSEGMENT_ENTRY;

typedef struct GATE_ENTRY
{
	unsigned	Offset0		:	16;
	unsigned	Selector	:	16;
	unsigned	Parametrs	:	 5;
	unsigned	Reserv		:	 3;
	unsigned	Type        :	 4;
	unsigned	IsGegment	:	 1;
	unsigned	DPL			:	 2;
	unsigned	P			:	 1;
	unsigned	Offset1		:	16;
}*PGATE_ENTRY;

typedef union DT_ENTRY
{
	GATE_ENTRY		Gate;
	SEGMENT_ENTRY	Segment;
} *PDT_ENTRY;

struct GATE_REF 
{
	ULONG		Offset;
	USHORT		Selector;
};

typedef struct X86_TAB 
{
	unsigned short	Reserv;
	unsigned short	Limit; 
	PDT_ENTRY       Table;
} *PX86_TAB; 

struct _KiIoAccessMap
{
	/*000*/	   UCHAR DirectionMap[0x20];
	/*020*/	   UCHAR IoMap[0x2004];
};

struct _EXCEPTION_REGISTRATION_RECORD;

struct _KTRAP_FRAME
{
	/*000*/	   ULONG DbgEbp;
	/*004*/	   ULONG DbgEip;
	/*008*/	   ULONG DbgArgMark;
	/*00C*/	   ULONG DbgArgPointer;
	/*010*/	   ULONG TempSegCs;
	/*014*/	   ULONG TempEsp;
	/*018*/	   ULONG Dr0;
	/*01C*/	   ULONG Dr1;
	/*020*/	   ULONG Dr2;
	/*024*/	   ULONG Dr3;
	/*028*/	   ULONG Dr6;
	/*02C*/	   ULONG Dr7;
	/*030*/	   ULONG SegGs;
	/*034*/	   ULONG SegEs;
	/*038*/	   ULONG SegDs;
	/*03C*/	   ULONG Edx;
	/*040*/	   ULONG Ecx;
	/*044*/	   ULONG Eax;
	/*048*/	   ULONG PreviousPreviousMode;
	/*04C*/	   _EXCEPTION_REGISTRATION_RECORD *ExceptionList;
	/*050*/	   ULONG SegFs;
	/*054*/	   ULONG Edi;
	/*058*/	   ULONG Esi;
	/*05C*/	   ULONG Ebx;
	/*060*/	   ULONG Ebp;
	/*064*/	   ULONG ErrCode;
	/*068*/	   ULONG Eip;
	/*06C*/	   ULONG SegCs;
	/*070*/	   ULONG EFlags;
	/*074*/	   ULONG HardwareEsp;
	/*078*/	   ULONG HardwareSegSs;
	/*07C*/	   ULONG V86Es;
	/*080*/	   ULONG V86Ds;
	/*084*/	   ULONG V86Fs;
	/*088*/	   ULONG V86Gs;
};

struct _KTSS
{
	/*000*/	   USHORT Backlink;
	/*002*/	   USHORT Reserved0;
	/*004*/	   ULONG Esp0;
	/*008*/	   USHORT Ss0;
	/*00A*/	   USHORT Reserved1;
	/*00C*/	   ULONG NotUsed1[0x4];
	/*01C*/	   ULONG CR3;
	/*020*/	   ULONG Eip;
	/*024*/	   ULONG EFlags;
	/*028*/	   ULONG Eax;
	/*02C*/	   ULONG Ecx;
	/*030*/	   ULONG Edx;
	/*034*/	   ULONG Ebx;
	/*038*/	   ULONG Esp;
	/*03C*/	   ULONG Ebp;
	/*040*/	   ULONG Esi;
	/*044*/	   ULONG Edi;
	/*048*/	   USHORT Es;
	/*04A*/	   USHORT Reserved2;
	/*04C*/	   USHORT Cs;
	/*04E*/	   USHORT Reserved3;
	/*050*/	   USHORT Ss;
	/*052*/	   USHORT Reserved4;
	/*054*/	   USHORT Ds;
	/*056*/	   USHORT Reserved5;
	/*058*/	   USHORT Fs;
	/*05A*/	   USHORT Reserved6;
	/*05C*/	   USHORT Gs;
	/*05E*/	   USHORT Reserved7;
	/*060*/	   USHORT LDT;
	/*062*/	   USHORT Reserved8;
	/*064*/	   USHORT Flags;
	/*066*/	   USHORT IoMapBase;
	/*068*/	   _KiIoAccessMap IoMaps;
	/*208C*/   UCHAR IntDirectionMap[0x20];
};

union DR6
{
	DWORD Value;
	struct
	{
		unsigned	B0	: 1;
		unsigned	B1	: 1;
		unsigned	B2	: 1;
		unsigned	B3	: 1;
		unsigned		: 9;
		unsigned	BD  : 1;
		unsigned	BS  : 1;
		unsigned	BT	: 1;
		unsigned		: 16;
	};
};

union DR7
{
	DWORD Value;
	struct 
	{
		unsigned	L0 : 1;
		unsigned	G0 : 1;
		unsigned	L1 : 1;
		unsigned	G1 : 1;
		unsigned	L2 : 1;
		unsigned	G2 : 1;
		unsigned	L3 : 1;
		unsigned	G3 : 1;
		unsigned	LE : 1;
		unsigned	GE : 1;
		unsigned	   : 3;
		unsigned	GD : 1;
		unsigned	   : 2;
		unsigned	RWE0:2;
		unsigned	LEN0:2;
		unsigned	RWE1:2;
		unsigned	LEN1:2;
		unsigned	RWE2:2;
		unsigned	LEN2:2;
		unsigned	RWE3:2;
		unsigned	LEN3:2;
	};
};

union _PTE_PAE
{
	ULONGLONG Value;
	union
	{
		struct 
		{
			ULONG Valid : 01;//00
			ULONG Write : 01;//01
			ULONG Owner : 01;//02
			ULONG WriteThrough : 01;//03
			ULONG CacheDisable : 01;//04
			ULONG Accessed : 01;//05
			ULONG Dirty : 01;//06
			ULONG LargePage : 01;//07
			ULONG Global : 01;//08
			ULONG CopyOnWrite : 01;//09
			ULONG Prototype : 01;//10
			ULONG reserved0 : 01;//11
		};
		struct  
		{
			ULONGLONG Flags : 12;
			ULONGLONG PageFrameNumber : 26;//12
			ULONGLONG reserved1 : 26;//38
		};
	};
	struct  
	{
		struct
		{
			/*0000*/ULONG Valid : 01;//00
			/*0000*/ULONG PageFileLow : 04;//01
			/*0000*/ULONG Protection : 05;//05
			/*0000*/ULONG Prototype : 01;//10
			/*0000*/ULONG Transition : 01;//11
			/*0000*/ULONG Unused : 20;//12
		};
		ULONG PageFileHigh;
	};
};
#define PDI_SHIFT_X86    22
#define PDI_SHIFT_X86PAE 21

const ULONG PX_SELFMAP_PAE = 3;
const ULONG PTE_BASE_PAE = PX_SELFMAP_PAE << 30;
const ULONG PDE_BASE_PAE = PTE_BASE_PAE + (PX_SELFMAP_PAE << 21);
const ULONG PPE_BASE_PAE = PDE_BASE_PAE + (PX_SELFMAP_PAE << 12);

#define PTE_PAE(i, j, k) ((_PTE_PAE*)((PX_SELFMAP_PAE << 30) + ((ULONG)(i) << 21) + ((ULONG)(j) << 12) + ((ULONG)(k) << 3) ))
#define PDE_PAE(j, k) PTE_PAE(PX_SELFMAP_PAE, j, k)
#define PPE_PAE(k) PTE_PAE(PX_SELFMAP_PAE, PX_SELFMAP_PAE, k)

#define PTE_PAE_L(V) (&((_PTE_PAE*)PTE_BASE_PAE)[(DWORD)(V) >> 12])
#define PDE_PAE_L(V) (&((_PTE_PAE*)PDE_BASE_PAE)[(DWORD)(V) >> 21])
#define PPE_PAE_L(V) (&((_PTE_PAE*)PPE_BASE_PAE)[(DWORD)(V) >> 30])

//
// Page protections
//

#define MM_ZERO_ACCESS         0  // this value is not used.
#define MM_READONLY            1
#define MM_EXECUTE             2
#define MM_EXECUTE_READ        3
#define MM_READWRITE           4  // bit 2 is set if this is writable.
#define MM_WRITECOPY           5
#define MM_EXECUTE_READWRITE   6
#define MM_EXECUTE_WRITECOPY   7

#define MM_NOCACHE            0x8
#define MM_GUARD_PAGE         0x10
#define MM_DECOMMIT           0x10   //NO_ACCESS, Guard page
#define MM_NOACCESS           0x18   //NO_ACCESS, Guard_page, nocache.
#define MM_UNKNOWN_PROTECTION 0x100  //bigger than 5 bits!
#define MM_LARGE_PAGES        0x111

#define MM_PROTECTION_WRITE_MASK     4
#define MM_PROTECTION_COPY_MASK      1
#define MM_PROTECTION_OPERATION_MASK 7 // mask off guard page and nocache.
#define MM_PROTECTION_EXECUTE_MASK   2

union _PTE_X86
{
	ULONG Value;
	struct
	{
		ULONG Valid : 01;//00
		ULONG Write : 01;//01
		ULONG Owner : 01;//02
		ULONG WriteThrough : 01;//03
		ULONG CacheDisable : 01;//04
		ULONG Accessed : 01;//05
		ULONG Dirty : 01;//06
		ULONG LargePage : 01;//07
		ULONG Global : 01;//08
		ULONG CopyOnWrite : 01;//09
		ULONG Prototype : 01;//10
		ULONG reserved : 01;//11
		ULONG PageFrameNumber : 20;//12
	};
	struct
	{
		/*0000*/ULONG Valid : 01;//00
		/*0000*/ULONG PageFileLow : 04;//01
		/*0000*/ULONG Protection : 05;//05
		/*0000*/ULONG Prototype : 01;//10
		/*0000*/ULONG Transition : 01;//11
		/*0000*/ULONG PageFileHigh : 20;//12
	};
};

extern ULONG PX_SELFMAP_X86, PTE_BASE_X86, PDE_BASE_X86;

#define INIT_PTE_CONSTS_X86(i) PX_SELFMAP_X86 = i;\
	PTE_BASE_X86 = PX_SELFMAP_X86 << 22;\
	PDE_BASE_X86 = PTE_BASE_X86 + (PX_SELFMAP_X86 << 12);

#define PTE_X86(i, j) ((_PTE_X86*)((PX_SELFMAP_X86 << 22) + ((ULONG)(i) << 12) + ((ULONG)(j) << 2) ))
#define PDE_X86(j) PTE_X86(PX_SELFMAP_X86, j)

#define PTE_X86_L(V) (&((_PTE_X86*)PTE_BASE_X86)[(DWORD)(V) >> 12])
#define PDE_X86_L(V) (&((_PTE_X86*)PDE_BASE_X86)[(DWORD)(V) >> 22])

#pragma pack(pop)

enum BREAKPOINT_TYPE
{
	Execute, WriteData, ReadData = 3
};

#define TRACE_FLAG	0x100
#define RESUME_FLAG 0x10000

#define SET_TRACE_FLAG() \
{\
	__asm{ pushfd }\
	__asm{ or dword ptr [esp],TRACE_FLAG }\
	__asm{ popfd }\
	__asm{ nop }\
}

#define DEL_TRACE_FLAG() \
{\
	__asm{ pushfd }\
	__asm{ and dword ptr [esp],~TRACE_FLAG }\
	__asm{ popfd }\
	__asm{ nop }\
}

#define DbgBreak() SET_TRACE_FLAG()
#define __DbgBreak() if (IsDebuggerPresent()) SET_TRACE_FLAG()
#define __DbgPrint if (IsDebuggerPresent()) DbgPrint
#define DbgBreakEx(condition) if (condition) SET_TRACE_FLAG()
#define SET_TIMEOUT(time,seconds) time.QuadPart = -(__int64)(10000000 * (seconds));

#pragma warning(disable : 4035 )

inline ULONG bswap_4(ULONG u)
{
	__asm { mov eax,u }
	__asm { bswap eax }
}

inline USHORT bswap_2(USHORT s)
{
	__asm { mov ax,s }
	__asm { bswap eax }
	__asm { rol eax,16}
}

#pragma warning(default : 4035 )
