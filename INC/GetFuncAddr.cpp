#define WIN32_LEAN_AND_MEAN
#include "../inc/StdAfx.h"

_NT_BEGIN
#include "../inc/nobase.h"

//#define _PRINT_CPP_NAMES_
#include "../inc/asmfunc.h"

char __fastcall fmemcmp(
						const void *buf1,
						const void *buf2,
						size_t count
						)ASM_FUNCTION;

PVOID __fastcall get_hmod(PCWSTR lpModuleName)
{
	CPP_FUNCTION;

	if (!*lpModuleName)
	{
		return CONTAINING_RECORD(((NT::_TEB*)NtCurrentTeb())->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList.Flink->Flink, 
			_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)->DllBase;
	}

	HMODULE hmod;
	UNICODE_STRING DllName = { 
		(USHORT)wcslen(lpModuleName) * sizeof(WCHAR), 
		DllName.Length, 
		const_cast<PWSTR>(lpModuleName) 
	};
	if (0 > LdrLoadDll(0, 0, &DllName, &hmod)) __debugbreak();
	return hmod;
}

PVOID __fastcall GetFuncAddressEx(PIMAGE_DOS_HEADER pidh, PCSTR lpsz)
{
	CPP_FUNCTION;

	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pidh, pidh->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(pidh, 
		pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD AddressOfNames = (PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfNames);
	PDWORD AddressOfFunctions = (PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfFunctions);
	PWORD AddressOfNameOrdinals = (PWORD)RtlOffsetToPointer(pidh, pied->AddressOfNameOrdinals);

	DWORD a = 0, b = pied->NumberOfNames, o;

	SIZE_T len = strlen(lpsz) + 1;

	if (b) 
	{
		do
		{
			char i = fmemcmp(lpsz, RtlOffsetToPointer(pidh, AddressOfNames[o = (a + b) >> 1]), len);
			if (!i)
			{
				PVOID pv = RtlOffsetToPointer(pidh, AddressOfFunctions[AddressOfNameOrdinals[o]]);

				if ((ULONG_PTR)pv - (ULONG_PTR)pied < pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
				{
					ANSI_STRING as = { (USHORT)len, as.Length, const_cast<PSTR>(lpsz) };
					if (0 > LdrGetProcedureAddress((HMODULE)pidh, &as, 0, &pv)) return 0;
				}

				return pv;
			}

			if (0 > i) b = o; else a = o + 1;

		} while (a < b);
	}

	return 0;
}

_NT_END
