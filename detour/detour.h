#pragma once

struct T_HOOK_ENTRY 
{
	_Inout_ void** pThunk;
	// pointer on variable which hold:
	// In: where to put the hook ( *pThunk -> func)
	// Out: pointer to place to execute original code ( *pThunk -> trump)
	_Inout_ PVOID hook;
	// In: pointer to hook function. so *pThunk redirected to hook
	// Out: original value of *pThunk ( func )
	union Z_DETOUR_TRAMPOLINE* pTramp;
};

/************************************************************************/
/* 
typical case:

before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_RtlDispatchAPC = RtlDispatchAPC; // initialized by loader

RtlDispatchAPC:
00007FFAB20AF6D0  mov         r11,rsp 
00007FFAB20AF6D3  mov         qword ptr [r11+8],rbx 
00007FFAB20AF6D7  mov         qword ptr [r11+10h],rsi


--------------------------------------------------------------------------
after: TrHook(&__imp_RtlDispatchAPC, hook_RtlDispatchAPC);
--------------------------------------------------------------------------

RtlDispatchAPC:
00007FFB876AF6D0  jmp         hook_RtlDispatchAPC
00007FFB876AF6D7  mov         qword ptr [r11+10h],rsi 

trampoline:
00007FFA3225FFB8  mov         r11,rsp 
00007FFA3225FFBB  mov         qword ptr [r11+8],rbx 
00007FFA3225FFBF  jmp         RtlDispatchAPC + 7 (7FFB876AF6D7h) 


__imp_RtlDispatchAPC = trampoline;

//////////////////////////////////////////////////////////////////////////
x86:
before:
-------------------------------------------------------------------------
#pragma comment(linker, "/alternatename:___imp_RtlActivateActivationContextUnsafeFast=__imp_@RtlActivateActivationContextUnsafeFast@8")

EXTERN_C PVOID __imp_RtlActivateActivationContextUnsafeFast = RtlActivateActivationContextUnsafeFast; // initialized by loader

771F6FBB  int         3    
771F6FBC  int         3    
771F6FBD  int         3    
771F6FBE  int         3    
771F6FBF  int         3    
RtlActivateActivationContextUnsafeFast:
771F6FC0  mov         edi,edi 
771F6FC2  push        ebp  

--------------------------------------------------------------------------
after: TrHook(&__imp_RtlActivateActivationContextUnsafeFast, hook_RtlActivateActivationContextUnsafeFast);
--------------------------------------------------------------------------

__imp_RtlActivateActivationContextUnsafeFast = 771F6FC2 ( RtlActivateActivationContextUnsafeFast + 2 )

771F6FBB  jmp         hook_RtlActivateActivationContextUnsafeFast
RtlActivateActivationContextUnsafeFast:
771F6FC0  jmp         771F6FBB 
771F6FC2  push        ebp  

*/
/************************************************************************/


//////////////////////////////////////////////////////////////////////////
// 

void __cdecl Nop_Print(_In_z_ _Printf_format_string_ PCSTR , ...);

#ifdef _X86_
#define __IMP(x) _imp__ ## x
#else
#define __IMP(x) __imp_ ## x
#endif

EXTERN_C PVOID __IMP(DbgPrint);
EXTERN_C PVOID __IMP(Dbg_Print);

// enable debug output
#define DBG_PRINT_ON() __IMP(Dbg_Print) = __IMP(DbgPrint)

// disable debug output ( this is by default)
#define DBG_PRINT_OFF() __IMP(Dbg_Print) = Nop_Print

struct ThreadInfo;

// suspend all threads in process, except current
NTSTATUS NTAPI SuspendAll(_Out_ ThreadInfo** ppti);

// resume all suspended threads and free pti
void NTAPI ResumeAndFree(_In_ ThreadInfo* pti);

// make IAT writable
NTSTATUS NTAPI TrInit(PVOID ImageBase = &__ImageBase);

void NTAPI TrHook(_In_ T_HOOK_ENTRY* entry, _In_ ULONG n, _In_opt_ ThreadInfo* pti = 0);

void NTAPI TrUnHook(_In_ T_HOOK_ENTRY* entry, _In_ ULONG n, _In_opt_ ThreadInfo* pti = 0);

// identical by sense ( first 2 parameters) to DetourAttach ( https://github.com/microsoft/Detours/wiki/DetourAttach )
// if not need unhook
// same as: 
// T_HOOK_ENTRY entry = { p__imp, hook }; 
// return TrHook(&entry, 1, pti);
NTSTATUS NTAPI TrHook(_Inout_ void** p__imp, _In_ PVOID hook, _In_opt_ ThreadInfo* pti = 0);

#define _DECLARE_T_HOOK(pfn) EXTERN_C extern PVOID __imp_ ## pfn;

#define DECLARE_T_HOOK_X86(pfn, n) _DECLARE_T_HOOK(pfn) __pragma(comment(linker, _CRT_STRINGIZE(/alternatename:___imp_##pfn##=__imp__##pfn##@##n)))

#ifdef _M_IX86
#define DECLARE_T_HOOK(pfn, n) DECLARE_T_HOOK_X86(pfn, n)
#else
#define DECLARE_T_HOOK(pfn, n) _DECLARE_T_HOOK(pfn)
#endif

#define T_HOOKS_BEGIN(name) T_HOOK_ENTRY name[] = {
#define T_HOOK(pfn) { &__imp_ ## pfn, hook_ ## pfn }
#define T_HOOKS_END() };

