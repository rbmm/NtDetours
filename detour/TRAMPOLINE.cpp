#include "StdAfx.h"
#include "LDasm.h"
_NT_BEGIN
#include <ntintsafe.h>

#include "threads.h"
#include "trampoline.h"

#ifdef _WIN64
C_ASSERT(sizeof(Z_DETOUR_TRAMPOLINE)==0x40);
#endif

bool IsBigDelta(LONG_PTR rel32)
{
	return rel32 != (LONG)rel32;
}

#ifdef _WIN64
#define IF_BIG_DELTA(delta) if (IsBigDelta(delta)) return 0;
#else
#define IF_BIG_DELTA(delta)
#endif

class Z_DETOUR_REGION 
{
	friend Z_DETOUR_TRAMPOLINE;

	Z_DETOUR_REGION* next;
	Z_DETOUR_TRAMPOLINE* First;
	LONG dwRef;
	Z_DETOUR_TRAMPOLINE first[];

	static Z_DETOUR_REGION* spRegion;

	~Z_DETOUR_REGION();

	Z_DETOUR_REGION();

	Z_DETOUR_TRAMPOLINE* alloc();

	void free(Z_DETOUR_TRAMPOLINE* Next)
	{
		Next->Next = First, First = Next;

		Release();
	}

	void Release()
	{
		if (!--dwRef)
		{
			delete this;
		}
	}

	void operator delete(PVOID BaseAddress)
	{
		SIZE_T RegionSize = 0;
		NtFreeVirtualMemory(NtCurrentProcess(), &BaseAddress, &RegionSize, MEM_RELEASE);
	}

#ifdef _WIN64
	void* operator new(size_t, ULONG_PTR min, ULONG_PTR max);
#else
	void* operator new(size_t);
#endif

	static Z_DETOUR_TRAMPOLINE* _alloc(void* pvTarget);

	static void _free(Z_DETOUR_TRAMPOLINE* pTramp);

	static ULONG GetAllocationGranularity()
	{
		SYSTEM_BASIC_INFORMATION sbi;
		if (0 > NtQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), 0)) __debugbreak();
		return sbi.AllocationGranularity;
	}

public:
	static ULONG gAllocationGranularity;
};

Z_DETOUR_REGION* Z_DETOUR_REGION::spRegion = 0;
ULONG Z_DETOUR_REGION::gAllocationGranularity = Z_DETOUR_REGION::GetAllocationGranularity();

Z_DETOUR_REGION::~Z_DETOUR_REGION()
{
	Z_DETOUR_REGION** ppRegion = &spRegion, *pRegion;

	while ((pRegion = *ppRegion) != this)
	{
		ppRegion = &pRegion->next;
	}

	*ppRegion = next;
}

Z_DETOUR_REGION::Z_DETOUR_REGION() : first{}
{
	dwRef = 1;

	next = spRegion, spRegion = this;

	ULONG n = (gAllocationGranularity - sizeof(Z_DETOUR_REGION)) / sizeof(Z_DETOUR_TRAMPOLINE);

	Z_DETOUR_TRAMPOLINE* Next = first, *Prev = 0;
	do 
	{
		Next->Next = Prev, Prev = Next++;
	} while (--n);

	First = Prev;
}

Z_DETOUR_TRAMPOLINE* Z_DETOUR_REGION::alloc()
{
	if (Z_DETOUR_TRAMPOLINE* Next = First)
	{
		dwRef++;

		First = Next->Next;

		return Next;
	}

	return 0;
}

#ifdef _WIN64

void* Z_DETOUR_REGION::operator new(size_t, ULONG_PTR min, ULONG_PTR max)
{
	ULONG_PTR addr, add = gAllocationGranularity - 1, mask = ~add;

	MEMORY_BASIC_INFORMATION mbi; 
	do 
	{
		if (0 > NtQueryVirtualMemory(NtCurrentProcess(),
			(void*)min, MemoryBasicInformation, &mbi, sizeof(mbi), 0)) return NULL;

		min = (UINT_PTR)mbi.BaseAddress + mbi.RegionSize;

		if (mbi.State == MEM_FREE)
		{
			addr = ((UINT_PTR)mbi.BaseAddress + add) & mask;

			if (addr < min && gAllocationGranularity <= (min - addr))
			{
				SIZE_T RegionSize = gAllocationGranularity;

				switch (NtAllocateVirtualMemory(NtCurrentProcess(), (void**)&addr, 0, 
					&RegionSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE))
				{
				case STATUS_CONFLICTING_ADDRESSES:
					min = (UINT_PTR)mbi.BaseAddress;
					break;
				case STATUS_SUCCESS:
					return (PVOID)addr;
				default: 
					return 0;
				}
			}
		}

	} while (min < max);

	return NULL;
}

void ExpandRange(ULONG_PTR a, ULONG_PTR b, ULONG_PTR& min, ULONG_PTR& max)
{
	ULONG_PTR add = Z_DETOUR_REGION::gAllocationGranularity - 1, mask = ~add, _a, _b;

	_b = (a + 0x80000000) & mask;
	_a = (b + add - 0x80000000) & mask;

	min = b < _a ? 0 : _a;
	max = _b < a ? ULONG_PTR_MAX : _b;
}

BOOL GetRangeForAddress(PVOID pv, ULONG_PTR& min, ULONG_PTR& max)
{
	PVOID hmod;
	if (hmod = RtlPcToFileHeader(pv, &hmod))
	{
		if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(hmod))
		{
			ExpandRange((ULONG_PTR)hmod, (ULONG_PTR)hmod + pinth->OptionalHeader.SizeOfImage, min, max);
			return TRUE;
		}
		return FALSE;
	}

	MEMORY_BASIC_INFORMATION mbi;
	if (0 <= NtQueryVirtualMemory(NtCurrentProcess(), pv, MemoryBasicInformation, &mbi, sizeof(mbi), 0))
	{
		if (mbi.State == MEM_COMMIT)
		{
			PVOID AllocationBase = mbi.AllocationBase;

			do 
			{
				pv = (PBYTE)mbi.BaseAddress + mbi.RegionSize;

				if (0 > NtQueryVirtualMemory(NtCurrentProcess(), pv, MemoryBasicInformation, &mbi, sizeof(mbi), 0))
				{
					return FALSE;
				}

			} while (mbi.State == MEM_COMMIT && mbi.AllocationBase == AllocationBase);

			ExpandRange((ULONG_PTR)AllocationBase, (ULONG_PTR)pv, min, max);

			return TRUE;
		}
	}

	return FALSE;
}

#else

void* Z_DETOUR_REGION::operator new(size_t)
{
	SIZE_T RegionSize = gAllocationGranularity;

	PVOID BaseAddress = 0;

	return 0 > NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, 
		&RegionSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE) ? 0 : BaseAddress;
}

#endif // _WIN64

void Z_DETOUR_REGION::_free(Z_DETOUR_TRAMPOLINE* pTramp)
{
	if (Z_DETOUR_REGION* pRegion = spRegion)
	{
		do 
		{
			if ((ULONG_PTR)pTramp - (ULONG_PTR)pRegion < gAllocationGranularity)
			{
				pRegion->free(pTramp);

				return ;
			}
		} while (pRegion = pRegion->next);
	}

	__debugbreak();
}

Z_DETOUR_TRAMPOLINE* Z_DETOUR_REGION::_alloc([[maybe_unused]] void* pvTarget)
{
#ifdef _WIN64
	ULONG_PTR min, max, cb;

	if (!GetRangeForAddress(pvTarget, min, max))
	{
		return 0;
	}

	cb = max - min;

	Z_DETOUR_TRAMPOLINE* pTramp;

	Z_DETOUR_REGION* pRegion = spRegion;

	if (pRegion)
	{

		do 
		{
			if ((ULONG_PTR)pRegion - min < cb)
			{
				if (pTramp = pRegion->alloc())
				{
					return pTramp;
				}
			}

		} while (pRegion = pRegion->next);
	}

	if (pRegion = new(min, max) Z_DETOUR_REGION)
	{
		pTramp = pRegion->alloc();
		pRegion->Release();
		return pTramp;
	}

	return 0;
#else
	Z_DETOUR_TRAMPOLINE* pTramp;

	Z_DETOUR_REGION* pRegion = spRegion;

	if (pRegion)
	{
		do 
		{
			if (pTramp = pRegion->alloc())
			{
				return pTramp;
			}

		} while (pRegion = pRegion->next);
	}

	if (pRegion = new Z_DETOUR_REGION)
	{
		pTramp = pRegion->alloc();
		pRegion->Release();
		return pTramp;
	}

	return 0;
#endif
}

//////////////////////////////////////////////////////////////////////////

void* Z_DETOUR_TRAMPOLINE::operator new(size_t, void* pvTarget)
{
	return Z_DETOUR_REGION::_alloc(pvTarget);
}

void Z_DETOUR_TRAMPOLINE::operator delete(PVOID pv)
{
	Z_DETOUR_REGION::_free((Z_DETOUR_TRAMPOLINE*)pv);
}

enum {
	JMP_rel32 = 0xE9,
	JMP_rel8 = 0xEB,
	NOP = 0x90,
	INT3 = 0xCC,
};

NTSTATUS Z_DETOUR_TRAMPOLINE::Set()
{
	struct {
		ULONG op;
		BYTE pad[3];
		BYTE jmp_e9;
		union {
			LONG_PTR rel;

			struct {
				LONG rel32;
				USHORT fbe9; // jmp $-7
			};
		};
	} j;

	// try jmp rel32 -> pvDetour

	j.rel = (LONG_PTR)pvDetour - ((LONG_PTR)pvJmp + SIZE_OF_JMP);

#ifdef _WIN64
	if (IsBigDelta(j.rel))
	{
		// try jmp rel32 -> jmp [pvDetour] in Z_DETOUR_TRAMPOLINE

		if (IsBigDelta(j.rel = (LONG_PTR)&ff25 - ((LONG_PTR)pvJmp + SIZE_OF_JMP)))
		{
			return STATUS_UNSUCCESSFUL;
		}
	}
#endif

	PVOID pv = pvJmp;

#ifdef _M_IX86
	j.fbe9 = 0xf9eb;
#endif//#ifdef _M_IX86

	SIZE_T size = cbRestore;
	NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &size, PAGE_EXECUTE_READWRITE, &j.op);

	if (0 > status)
	{
		return status;
	}

	j.jmp_e9 = JMP_rel32;

	memcpy(pvJmp, &j.jmp_e9, cbRestore);

	if (j.op != PAGE_EXECUTE_READWRITE)
	{
		ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &size, j.op, &j.op);
	}

	return STATUS_SUCCESS;
}

NTSTATUS Z_DETOUR_TRAMPOLINE::Remove()
{
	ULONG op;
	PVOID pv = pvJmp;

	SIZE_T size = cbRestore;

	NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &size, PAGE_EXECUTE_READWRITE, &op);

	if (0 > status)
	{
		return status;
	}

	memcpy(pvJmp, rbRestore, cbRestore);

	if (op != PAGE_EXECUTE_READWRITE)
	{
		ZwProtectVirtualMemory(NtCurrentProcess(), &pv, &size, op, &op);
	}

	return STATUS_SUCCESS;
}

BOOL detour_does_code_end_function(PBYTE pbCode)
{
__0:
	switch (pbCode[0])
	{
	case JMP_rel8:    // jmp +imm8
	case JMP_rel32:    // jmp +imm32
	case 0xe0:    // jmp eax
	case 0xc2:    // ret +imm8
	case 0xc3:    // ret
		return TRUE;

	case 0xf3:
		return pbCode[1] == 0xc3;  // rep ret

	case 0xff:
		return pbCode[1] == 0x25;  // jmp [+imm32]

	case 0x26:      // jmp es:
	case 0x2e:      // jmp cs:
	case 0x36:      // jmp ss:
	case 0x3e:      // jmp ds:
	case 0x64:      // jmp fs:
	case 0x65:      // jmp gs:
		pbCode++;
		goto __0;
	}

	return FALSE;
}

UCHAR detour_is_code_filler(PBYTE pbCode)
{
	// 1-byte through 11-byte NOPs.

	switch (pbCode[0])
	{
	case INT3: // int 3
	case NOP: // NOP
		return 1;

#ifdef _M_IX86
	case 0x8D:
		switch (pbCode[1])
		{
		case 0x9B: // lea ebx,[ebx]
			return pbCode[2] == 0x00 && pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 ? 6 : 0;
		case 0xA4: // lea esp,[esp]
			return pbCode[2] == 0x24 && pbCode[3] == 0x00 && 
				pbCode[4] == 0x00 && pbCode[5] == 0x00 && pbCode[6] == 0x00 ? 7 : 0;
		}
		break;
#endif//_M_IX86

	case 0x66:
		switch (pbCode[1])
		{
		case NOP:
			return 2;

		case 0x0F:
			switch (pbCode[2])
			{
			case 0x1F:
				switch (pbCode[3])
				{
				case 0x44:
					return pbCode[4] == 0x00 && pbCode[5] == 0x00 ? 6 : 0;

				case 0x84:
					return pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
						pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 ? 9 : 0;
				}
				break;
			}
			break;

		case 0x66:
			switch (pbCode[2])
			{
			case 0x0F:
				return pbCode[3] == 0x1F && pbCode[4] == 0x84 && pbCode[5] == 0x00 &&
					pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
					pbCode[9] == 0x00 ? 10 : 0;

			case 0x66:
				return pbCode[3] == 0x0F && pbCode[4] == 0x1F && pbCode[5] == 0x84 &&
					pbCode[6] == 0x00 && pbCode[7] == 0x00 && pbCode[8] == 0x00 &&
					pbCode[9] == 0x00 && pbCode[10] == 0x00 ? 11 : 0;
			}
			break;
		}
		break;

	case 0x0F:
		switch (pbCode[1])
		{
		case 0x1F:
			switch (pbCode[2])
			{
			case 0x00:
				return 3;
			
			case 0x40:
				return pbCode[3] == 0x00 ? 4 : 0;
			
			case 0x44:
				return pbCode[3] == 0x00 && pbCode[4] == 0x00 ? 5 : 0;
			
			case 0x80:
				return pbCode[3] == 0x00 && pbCode[4] == 0x00 && 
					pbCode[5] == 0x00 && pbCode[6] == 0x00 ? 7 : 0;
			
			case 0x84:
				return pbCode[3] == 0x00 && pbCode[4] == 0x00 && pbCode[5] == 0x00 &&
					pbCode[6] == 0x00 && pbCode[7] == 0x00 ? 8 : 0;
			}
			break;
		}
		break;
	}

	return 0;
}

namespace {

	void Adjust(ULONG n_fix, ULONG n_ext, PBYTE pbFixups[], PBYTE pbJmps[], PBYTE pbTargets[], PBYTE pbExtends[]) 
	{
		if (n_fix && n_ext)
		{
			do {
				PBYTE pbJmp = *pbJmps++;
				PBYTE pbTarget = *pbTargets++;
				PBYTE pbFixup = *pbFixups++;

				ULONG i = n_ext;
				PBYTE* ppb = pbExtends;

				do {

					PBYTE pbExtend = *ppb++;
					if (pbExtend < pbJmp) {
						if (pbTarget <= pbExtend) *pbFixup -= 4; // pbTarget: .. pbExtend[+4] .. Jmp pbTarget
					}
					else {
						if (pbExtend < pbTarget) *pbFixup += 4; // Jmp pbTarget .. pbExtend[+4] .. pbTarget
					}
				} while (--i);

			} while (--n_fix);      
		}
	}
}

PVOID Z_DETOUR_TRAMPOLINE::Init(PVOID pvTarget)
{
	ldasm_data ld;
	PBYTE code = (PBYTE)pvTarget, pDst = rbCode, pbCode, JmpTarget;
	BYTE len, cb = 0, ofs;
	cbRestore = SIZE_OF_JMP;
	LONG_PTR delta;
	
	BOOLEAN bMicroJmp;

	ULONG n_fix = 0, n_ext = 0;
	PBYTE pbFuxups[3];	// adresses of fixup inside trampoline
	PBYTE pbJmps[3];	// adresses of JMP/Jcc/Loop/Jrcx
	PBYTE pbTargets[3];	// targets  of JMP/Jcc/Loop/Jrcx
	PBYTE pbExtends[3];	// addresses of Jcc, extended from 2 to 6 bytes

__jmp:
	switch (code[0])
	{
#ifdef _M_IX86 // never see this on x64
	case 0x8B:
		// check for
		//------------
		// NOP | int 3
		// NOP | int 3
		// NOP | int 3
		// NOP | int 3
		// NOP | int 3
		//------------
		// mov edi,edi ; 8B FF | no trampoline used
		if (code[1] == 0xFF)
		{
			switch (code[-1])
			{
			case NOP:
				if (code[-2] == NOP && code[-3] == NOP && code[-4] == NOP && code[-5] == NOP)
				{
__np:
					pvJmp = code - 5;
					cbRestore = 7;
					memcpy(rbRestore, pvJmp, 7);
					return code + 2;
				}
				break;
			case INT3:
				if (code[-2] == INT3 && code[-3] == INT3 && code[-4] == INT3 && code[-5] == INT3)
				{
					goto __np;
				}
				break;
			}
		}
		break;
#endif//_M_IX86

	case JMP_rel32: // JMP rel32 | no trampoline used
		JmpTarget = code + 5 + *(LONG*)(code + 1);
		memcpy(rbRestore, pvTarget, 5);
		pvJmp = pvTarget;
		return JmpTarget;

	case JMP_rel8: // JMP rel8
		JmpTarget = code + 2 + *(CHAR*)(code + 1);

		code = JmpTarget, pvTarget = JmpTarget;

		goto __jmp;
	}

	do 
	{
		len = ldasm( pbCode = code, &ld, is_x64 );

		if (ld.flags & F_INVALID)
		{
			return 0;
		}

		memcpy(pDst, code, len);

		bMicroJmp = FALSE;

		if (ld.flags & F_RELATIVE)
		{
			if (ld.flags & F_DISP)
			{
				if (ld.disp_size != 4)
				{
					return 0;
				}

				// case 1: data access relocated
				delta = *(PLONG)(code + ld.disp_offset);
__1:

				delta += code - pDst;

				IF_BIG_DELTA(delta);

				*(PLONG)(pDst + ld.disp_offset) = (LONG)delta;
			}
			else if (ld.flags & F_IMM)
			{
				BYTE opcode = code[ld.opcd_offset];

				switch (ld.imm_size)
				{
				default:
					return 0;

				case 4:
					// case 2: JMP/Jcc rel32 relocated
					delta = *(PLONG)(code + ld.imm_offset);

					ld.disp_offset = ld.imm_offset;
					goto __1;

				case 1:
					if (ld.opcd_size != 1)
					{
						return 0;
					}

					delta = *(PCHAR)(code + ld.imm_offset);

					JmpTarget = code + len + delta;

					if ((ULONG_PTR)(JmpTarget - (PBYTE)pvTarget) < SIZE_OF_JMP)
					{
						bMicroJmp = TRUE;

						pbJmps[n_fix] = code;
						pbTargets[n_fix] = JmpTarget;
						pbFuxups[n_fix++] = pDst + ld.imm_offset;
					}

					if (opcode == JMP_rel8) // JMP rel8
					{
						if (bMicroJmp)
						{
							// case 3:
							break;
						}

						// case 4: JMP rel8 (2 bytes) extended (+3 bytes) to JMP rel32 (5 bytes) inside trampoline
						// this is end of function
						pDst[ld.opcd_offset] = JMP_rel32;// -> JMP rel32

						delta += code - pDst - 3;

						IF_BIG_DELTA(delta);

						*(PLONG)(pDst + ld.imm_offset) = (LONG)delta;

						pDst += 3;

						break;
					}

					if (bMicroJmp)
					{
						// case 5:
						break;
					}

					if (opcode - 0x70 > 0xF) // if (!Jxx)
					{
						// case 6: invalid target
						return 0;
					}

					// case 7: Jcc rel8 (2 bytes) extended (+4 bytes) to Jcc rel32 (6 bytes) inside trampoline

					pDst[ld.opcd_offset] = 0x0F;
					pDst[ld.opcd_offset+1] = 0x10 + opcode;

					delta += code - pDst - 4;

					IF_BIG_DELTA(delta);

					*(PLONG)(pDst + ld.imm_offset + 1) = (LONG)delta;

					pbExtends[n_ext++] = code;

					pDst += 4;

					if ((ofs = cb + len) < SIZE_OF_JMP)
					{
						if (!o1)
						{
							o1 = ofs;
						}
						else if (!o2)
						{
							o2 = ofs;
						}
					}
					break;
				}
			}
		}

		code += len, pDst += len;

		if (!bMicroJmp && detour_does_code_end_function(pbCode))
		{
			// case 8: function too small ( < 5 bytes )

			while ((cb += len) < SIZE_OF_JMP)
			{
				if (!(len = detour_is_code_filler(code)))
				{
					// case 9: Too few instructions !
					return 0;
				}
				code += len;
			}

			// not need set JMP to pvAfter
			goto __end;
		}

	} while ((cb += len) < SIZE_OF_JMP);

	// set JMP rel32 -> pvAfter

	delta = (LONG_PTR)code - (LONG_PTR)(pDst + SIZE_OF_JMP);

	IF_BIG_DELTA(delta);

	*pDst = JMP_rel32;
	memcpy(pDst + 1, &delta, 4);
	memcpy(rbRestore, pvTarget, SIZE_OF_JMP);

__end:

	pvJmp = pvTarget, pvAfter = code, cbCode = (UCHAR)(pDst - rbCode);

	Adjust(n_fix, n_ext, pbFuxups, pbJmps, pbTargets, pbExtends);

	return rbCode;
}

void Z_DETOUR_TRAMPOLINE::Expand(_Inout_ DTA* Lens)
{
	ULONG len;
	if (len = o1)
	{
		Lens->ofs1 = len;
		Lens->add1 = 4;
	}

	if (len = o2)
	{
		Lens->ofs2 = len;
		Lens->add2 = 4;
	}
}

_NT_END