#pragma once

struct DTA;

enum {
	SIZE_OF_JMP = 5
};

union Z_DETOUR_TRAMPOLINE 
{
	Z_DETOUR_TRAMPOLINE* Next;

	struct 
	{
		union {
			ULONG ff250000;
			struct {
				USHORT cbRestore;      // size of original target code.
				USHORT ff25;		   // jmp [pvDetour]
			};
		};
		ULONG  disp;
		PVOID  pvDetour;		// address of detour function.
		PVOID  pvJmp;			// address of modification in original code
		PVOID  pvAfter;			// first instruction after moved code.
		BYTE   rbCode[23];		// target code + Jmp pvAfter
		BYTE   cbCode;
		BYTE   rbRestore[7];	// saved original code.

		union {
			UCHAR o;
			struct {
				// Jxx rel8 -> Jxx rel32 ( + 4 bytes )
				UCHAR o1 : 4;
				UCHAR o2 : 4;
			};
		};
	};

	~Z_DETOUR_TRAMPOLINE(){}

	Z_DETOUR_TRAMPOLINE(PVOID pvDetour) : pvDetour(pvDetour), pvAfter(0), pvJmp(0), cbCode(0), o(0)
	{
		ff250000 = 0x25ff0000;
#if defined(_M_X64)  
		disp = 0;
#elif defined (_M_IX86)
		disp = (ULONG_PTR)&pvDetour;
#else
#error ##
#endif
		RtlFillMemoryUlong(rbCode, sizeof(rbCode), 0xcccccccc);
	}

	void* operator new(size_t, void* pvTarget);

	void operator delete(PVOID pv);

	PVOID Init(PVOID pvTarget);

	NTSTATUS Set();

	NTSTATUS Remove();

	void Expand(_Inout_ DTA* Lens);
};
