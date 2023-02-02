#pragma once

union DR6
{
	__int64 Value;
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
	__int64 Value;
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

enum BREAKPOINT_TYPE
{
	Execute, WriteData, ReadData = 3
};

#define TRACE_FLAG	0x100
#define RESUME_FLAG 0x10000

#define DbgBreak() __debugbreak()
#define __DbgBreak() if (IsDebuggerPresent()) __debugbreak()
#define __DbgPrint if (IsDebuggerPresent()) DbgPrint
#define DbgBreakEx(condition) if (condition) __debugbreak()

//#define _PX_SELFMAP ((ULONGLONG)0x1ED)

#define PTE_SHIFT 3
#define PTI_SHIFT 12
#define PDI_SHIFT 21
#define PPI_SHIFT 30
#define PXI_SHIFT 39

#define PTE_PER_PAGE 512
#define PDE_PER_PAGE 512
#define PPE_PER_PAGE 512
#define PXE_PER_PAGE 512

#define PTI_MASK_AMD64 (PTE_PER_PAGE - 1)
#define PDI_MASK_AMD64 (PDE_PER_PAGE - 1)
#define PPI_MASK (PPE_PER_PAGE - 1)
#define PXI_MASK (PXE_PER_PAGE - 1)
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

union _PTE
{
	ULONGLONG Value;

	struct  
	{
		ULONGLONG Valid : 01;//00
		ULONGLONG Write : 01;//01
		ULONGLONG Owner : 01;//02
		ULONGLONG WriteThrough : 01;//03
		ULONGLONG CacheDisable : 01;//04
		ULONGLONG Accessed : 01;//05
		ULONGLONG Dirty : 01;//06
		ULONGLONG LargePage : 01;//07
		ULONGLONG Global : 01;//08
		ULONGLONG CopyOnWrite : 01;//09
		ULONGLONG Prototype : 01;//10
		ULONGLONG reserved0 : 01;//11
		ULONGLONG PageFrameNumber : 36;//12
		ULONGLONG reserved1 : 04;//40
		ULONGLONG SoftwareWsIndex : 11;//52
		ULONGLONG NoExecute : 01;//63
	};

	struct
	{
		ULONGLONG Valid : 01;//00
		ULONGLONG PageFileLow : 04;//01
		ULONGLONG Protection : 05;//05
		ULONGLONG Prototype : 01;//10
		ULONGLONG Transition : 01;//11
		ULONGLONG UsedPageTableEntries : 10;//12
		ULONGLONG Reserved : 10;//22
		ULONGLONG PageFileHigh : 32;//32
	};
};

extern ULONGLONG PTE_BASE_X64, PDE_BASE_X64, PPE_BASE_X64, PXE_BASE_X64, PX_SELFMAP;

#define VIRTUAL_ADDRESS_BITS 48
#define VIRTUAL_ADDRESS_MASK ((((ULONGLONG)1) << VIRTUAL_ADDRESS_BITS) - 1)
#define VIRTUAL_ADDRESS(va) (VIRTUAL_ADDRESS_MASK & (ULONGLONG)(va))

#define PX_SELFMAP_MIN 0x100
#define PX_SELFMAP_MAX 0x1FF

#define INIT_PTE_CONSTS(i) PX_SELFMAP = i;\
	PTE_BASE_X64 = (~VIRTUAL_ADDRESS_MASK) + (PX_SELFMAP << PXI_SHIFT);\
	PDE_BASE_X64 = PTE_BASE_X64 + (PX_SELFMAP << PPI_SHIFT);\
	PPE_BASE_X64 = PDE_BASE_X64 + (PX_SELFMAP << PDI_SHIFT);\
	PXE_BASE_X64 = PPE_BASE_X64 + (PX_SELFMAP << PTI_SHIFT);

#define PTE(i, j, k, m) ((_PTE*)((~VIRTUAL_ADDRESS_MASK) + (PX_SELFMAP << PXI_SHIFT) + ((ULONGLONG)(i) << PPI_SHIFT) + ((ULONGLONG)(j) << PDI_SHIFT) + ((ULONGLONG)(k) << PTI_SHIFT) + ((ULONGLONG)(m) << PTE_SHIFT) ))
#define PDE(j, k, m) PTE(PX_SELFMAP, j, k, m)
#define PPE(k, m) PTE(PX_SELFMAP, PX_SELFMAP, k, m)
#define PXE(m) PTE(PX_SELFMAP, PX_SELFMAP, PX_SELFMAP, m)

#define PTE_X64_MASK ((VIRTUAL_ADDRESS_MASK >> PTI_SHIFT) << PTE_SHIFT)
#define PDE_X64_MASK ((VIRTUAL_ADDRESS_MASK >> PDI_SHIFT) << PTE_SHIFT)
#define PPE_X64_MASK ((VIRTUAL_ADDRESS_MASK >> PPI_SHIFT) << PTE_SHIFT)
#define PXE_X64_MASK ((VIRTUAL_ADDRESS_MASK >> PXI_SHIFT) << PTE_SHIFT)

#define PTE_X64_OFS(V) (PTE_X64_MASK & ((ULONGLONG)(V) >> (PTI_SHIFT - PTE_SHIFT)))
#define PDE_X64_OFS(V) (PDE_X64_MASK & ((ULONGLONG)(V) >> (PDI_SHIFT - PTE_SHIFT)))
#define PPE_X64_OFS(V) (PPE_X64_MASK & ((ULONGLONG)(V) >> (PPI_SHIFT - PTE_SHIFT)))
#define PXE_X64_OFS(V) (PXE_X64_MASK & ((ULONGLONG)(V) >> (PXI_SHIFT - PTE_SHIFT)))

#define PTE_X64_L(V) ((_PTE*)(PTE_BASE_X64 + PTE_X64_OFS(V)))
#define PDE_X64_L(V) ((_PTE*)(PDE_BASE_X64 + PDE_X64_OFS(V)))
#define PPE_X64_L(V) ((_PTE*)(PPE_BASE_X64 + PPE_X64_OFS(V)))
#define PXE_X64_L(V) ((_PTE*)(PXE_BASE_X64 + PXE_X64_OFS(V)))

#define PTE_X64_L_(V) (&((_PTE*)PTE_BASE_X64)[VIRTUAL_ADDRESS(V) >> PTI_SHIFT])
#define PDE_X64_L_(V) (&((_PTE*)PDE_BASE_X64)[VIRTUAL_ADDRESS(V) >> PDI_SHIFT])
#define PPE_X64_L_(V) (&((_PTE*)PPE_BASE_X64)[VIRTUAL_ADDRESS(V) >> PPI_SHIFT])
#define PXE_X64_L_(V) (&((_PTE*)PXE_BASE_X64)[VIRTUAL_ADDRESS(V) >> PXI_SHIFT])
