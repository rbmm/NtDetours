#pragma once

struct DTA 
{
	ULONG ofs1, ofs2;
	LONG  add1, add2;
};

struct ThreadInfo;

BOOLEAN MovePc(_In_ ThreadInfo* pti, _In_ ULONG_PTR PcFrom, _In_ ULONG_PTR PcTo, _In_ ULONG cb, _In_ DTA* Lens);

EXTERN_C
NTSYSAPI
ULONG
__cdecl
Dbg_Print (
		   _In_z_ _Printf_format_string_ PCSTR Format,
		   ...
		   );