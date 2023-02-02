*****************************************************************************************************
###### NTSTATUS NTAPI TrInit(PVOID ImageBase = &__ImageBase);
*****************************************************************************************************

make IAT writable.


look for [simple.cpp](https://github.com/microsoft/Detours/blob/main/samples/simple/simple.cpp)

**TimedSleepEx** calls the real **SleepEx** API through the ***TrueSleepEx*** function pointer.

```
static DWORD (WINAPI * TrueSleepEx)(DWORD dwMilliseconds, BOOL bAlertable) = SleepEx;

DWORD WINAPI TimedSleepEx(DWORD dwMilliseconds, BOOL bAlertable)
{
    ...
    DWORD ret = TrueSleepEx(dwMilliseconds, bAlertable);
    ...
}
```

**_don't do this !_** linker already defined
```
EXTERN_C PVOID __imp_SleepEx = SleepEx;
```
variable 
( for x86 this will be ***__imp__SleepEx@8*** and need use 
```
__pragma(comment(linker, "/alternatename:___imp_SleepEx=__imp__SleepEx@8"))
```
so use ***__imp_SleepEx*** instead ***TrueSleepEx*** and simply call api in the usual and convenient way.

any imported api SomeApi invoked via ***__imp_SomeApi*** ( delayed load via ***__imp_load_SomeApi*** ) pointer. use it !

example

```
//EXTERN_C extern PVOID __imp_SleepEx;
DECLARE_T_HOOK(SleepEx, 8)

DWORD WINAPI hook_SleepEx( _In_ DWORD dwMilliseconds, _In_ BOOL bAlertable )
{
	ULONG ret = SleepEx(dwMilliseconds, bAlertable);

	DbgPrint("%s(%x, %x) = %x\n", __FUNCTION__, dwMilliseconds, bAlertable, ret);

	return ret;
}

void DetoursDemo()
{
	DBG_PRINT_ON();

	if (0 <= TrInit())
	{
		ThreadInfo* pti;
		SuspendAll(&pti);

		DbgPrint("before: SleepEx = 0x%p\n", SleepEx);

		TrHook(&__imp_SleepEx, hook_SleepEx, pti);

		DbgPrint("after: SleepEx = 0x%p\n", SleepEx);

		ResumeAndFree(pti);

		union {
			PVOID pv;
			DWORD (WINAPI * fn_SleepEx)( _In_ DWORD dwMilliseconds, _In_ BOOL bAlertable );
		};

		if (pv = GetProcAddress(GetModuleHandleW(L"kernel32"), "SleepEx"))
		{
			if (QueueUserAPC((PAPCFUNC)OutputDebugStringA, GetCurrentThread(), (ULONG_PTR)"asynchronous procedure call...\n"))
			{
				fn_SleepEx(INFINITE, TRUE);
			}
		}
	}
}
```

typical debug output:

```
NT::ThreadInfo::ThreadInfo<000002196427D6A0>(0000000000000814)
NT::ThreadInfo::ThreadInfo<000002196427DBC0>(0000000000000128)
NT::ThreadInfo::ThreadInfo<000002196427E0E0>(00000000000023D0)
before: SleepEx = 0x00007FFED3DB06B0
0x00007FFED3DB06B0 -> 0x00007FF78BEB06C0 -> 0x00007FFE5394FFB8 [0x00007FFE5394FF98]
after: SleepEx = 0x00007FFE5394FFB8
NT::ThreadInfo::~ThreadInfo<000002196427E0E0>(00000000000023D0)
NT::ThreadInfo::~ThreadInfo<000002196427DBC0>(0000000000000128)
NT::ThreadInfo::~ThreadInfo<000002196427D6A0>(0000000000000814)
asynchronous procedure call...
NT::hook_SleepEx(ffffffff, 1) = c0
```

another example, with unhook:

```
DWORD WINAPI hook_SleepEx( _In_ DWORD dwMilliseconds, _In_ BOOL bAlertable )
{
	// don't use any [TrueSleepEx](https://github.com/microsoft/Detours/blob/main/samples/simple/simple.cpp#L23) !! 
	ULONG ret = SleepEx(dwMilliseconds, bAlertable);

	DbgPrint("%s(%x, %x) = %x\n", __FUNCTION__, dwMilliseconds, bAlertable, ret);

	return ret;
}

int
WINAPI
hook_MessageBoxW(
				 _In_opt_ HWND hWnd,
				 _In_opt_ PCWSTR lpText,
				 _In_opt_ PCWSTR lpCaption,
				 _In_ UINT uType)
{
	// don't use any [Real_MessageBoxW](https://raw.githubusercontent.com/microsoft/Detours/main/samples/traceapi/_win32.cpp) !! 
	
	int ret = MessageBoxW(hWnd, lpText, __FUNCTIONW__, uType);

	DbgPrint("%s(\"%S\", \"%S\") = %x\n", __FUNCTION__, lpText, lpCaption, ret);

	return ret;
}

DECLARE_T_HOOK(SleepEx, 8)
DECLARE_T_HOOK(MessageBoxW, 16)

T_HOOKS_BEGIN(gHooks)
	T_HOOK(SleepEx),
	T_HOOK(MessageBoxW),
T_HOOKS_END()

void DemoApiCalls()
{
	union {
		PVOID pv;
		DWORD (WINAPI * fn_SleepEx)( _In_ DWORD dwMilliseconds, _In_ BOOL bAlertable );
		int (WINAPI * fn_MessageBoxW)( _In_opt_ HWND hWnd, _In_opt_ LPCWSTR lpText, _In_opt_ LPCWSTR lpCaption, _In_ UINT uType);
	};

	if (pv = GetProcAddress(GetModuleHandleW(L"kernel32"), "SleepEx"))
	{
		if (QueueUserAPC((PAPCFUNC)OutputDebugStringA, GetCurrentThread(), (ULONG_PTR)"asynchronous procedure call...\n"))
		{
			fn_SleepEx(INFINITE, TRUE);
		}
	}

	if (pv = GetProcAddress(GetModuleHandleW(L"user32"), "MessageBoxW"))
	{
		fn_MessageBoxW(0, L"[some text]", 0, MB_ICONINFORMATION);
	}
}

void DetoursDemo()
{
	DBG_PRINT_ON();

	if (0 <= TrInit())
	{
		ThreadInfo* pti;
		SuspendAll(&pti);
		TrHook(gHooks, _countof(gHooks), pti);
		ResumeAndFree(pti);

		DemoApiCalls();

		SuspendAll(&pti);
		TrUnHook(gHooks, _countof(gHooks), pti);
		ResumeAndFree(pti);

		DemoApiCalls();
	}
}

NT::ThreadInfo::ThreadInfo<0000026DEA5AD6D0>(00000000000017E8)
NT::ThreadInfo::ThreadInfo<0000026DEA5ADBF0>(00000000000013E0)
NT::ThreadInfo::ThreadInfo<0000026DEA5AE110>(00000000000002D4)
0x00007FFED3DB06B0 -> 0x00007FF693E10790 -> 0x00007FFE5394FFB8 [0x00007FFE5394FF98]
0x00007FFED41CA160 -> 0x00007FF693E10720 -> 0x00007FFE5430FFB8 [0x00007FFE5430FF98]
NT::ThreadInfo::~ThreadInfo<0000026DEA5AE110>(00000000000002D4)
NT::ThreadInfo::~ThreadInfo<0000026DEA5ADBF0>(00000000000013E0)
NT::ThreadInfo::~ThreadInfo<0000026DEA5AD6D0>(00000000000017E8)
asynchronous procedure call...
NT::hook_SleepEx(ffffffff, 1) = c0


---------------------------
NT::hook_MessageBoxW
---------------------------
[some text]
---------------------------
OK   
---------------------------

NT::hook_MessageBoxW("[some text]", "(null)") = 1

NT::ThreadInfo::ThreadInfo<0000026DEA5C7370>(0000000000001A84)
NT::ThreadInfo::ThreadInfo<0000026DEA5C7890>(0000000000000D1C)
NT::ThreadInfo::ThreadInfo<0000026DEA5E2950>(00000000000020C8)
NT::ThreadInfo::ThreadInfo<0000026DEA5E2E70>(0000000000000D18)
NT::ThreadInfo::ThreadInfo<0000026DEA5E3390>(0000000000001974)
NT::ThreadInfo::ThreadInfo<0000026DEA5DD3D0>(00000000000023E0)
NT::ThreadInfo::ThreadInfo<0000026DEA5DD8F0>(0000000000001C58)
NT::ThreadInfo::~ThreadInfo<0000026DEA5DD8F0>(0000000000001C58)
NT::ThreadInfo::~ThreadInfo<0000026DEA5DD3D0>(00000000000023E0)
NT::ThreadInfo::~ThreadInfo<0000026DEA5E3390>(0000000000001974)
NT::ThreadInfo::~ThreadInfo<0000026DEA5E2E70>(0000000000000D18)
NT::ThreadInfo::~ThreadInfo<0000026DEA5E2950>(00000000000020C8)
NT::ThreadInfo::~ThreadInfo<0000026DEA5C7890>(0000000000000D1C)
NT::ThreadInfo::~ThreadInfo<0000026DEA5C7370>(0000000000001A84)

asynchronous procedure call...

---------------------------
Error
---------------------------
[some text]
---------------------------
OK   
---------------------------
```

*****************************************************************************************************
###### DBG_PRINT_ON() / DBG_PRINT_OFF()
*****************************************************************************************************

enable / disable debug output ( by default it disabled)


*****************************************************************************************************
###### NTSTATUS NTAPI SuspendAll(_Out_ ThreadInfo** ppti);
*****************************************************************************************************

enumerate threads in process via NtGetNextThread
check are cuttent thread ( ZwQueryInformationThread(ThreadBasicInformation) )
suspend thread ZwSuspendThread
save it context ZwGetContextThread
link thread info (handle/context) to list

*****************************************************************************************************
###### void NTAPI ResumeAndFree(_In_ ThreadInfo* pti);
*****************************************************************************************************

walk thread list ( pti )
resume thread
close it handle
free memory


*****************************************************************************************************
###### NTSTATUS NTAPI TrHook(_Inout_ void** p__imp, _In_ PVOID hook, _In_opt_ ThreadInfo* pti)
```
{
	T_HOOK_ENTRY entry = { p__imp, hook };
	return TrHook(&entry, 1, pti);
}
```
*****************************************************************************************************

simplified version, for hook single api and when not need unhook it
almost identical to [DetourAttach](https://github.com/microsoft/Detours/wiki/DetourAttach)
only difference - TrHook do actual patch just, when DetourAttach - after DetourTransactionCommit


*****************************************************************************************************
###### void NTAPI TrHook(_In_ T_HOOK_ENTRY* entry, _In_ ULONG n, _In_opt_ ThreadInfo* pti = 0);
*****************************************************************************************************

try allocate tramploline in -/+ 2GB range ( in 32 bit mode any address is ok) from patched region
hook api by set JMP hook at it begin and save original instruction inside trampoline
walk by thread list (optional) and if need (Pc in JMP) - adjust context of threads


exist several cases:

```
////////////////////////////////////////////////////////////////////////////////////////////////////////
// typical case:

-------------------------------------------------------------------------
before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_RtlDispatchAPC = RtlDispatchAPC;

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

////////////////////////////////////////////////////////////////////////////////////////////////////////
// x86 mov edi,edi:

#pragma comment(linker, "/alternatename:___imp_RtlActivateActivationContextUnsafeFast=__imp_@RtlActivateActivationContextUnsafeFast@8")

EXTERN_C PVOID __imp_RtlActivateActivationContextUnsafeFast = RtlActivateActivationContextUnsafeFast;

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

////////////////////////////////////////////////////////////////////////////////////////////////////////
// case 1: data access relocated

-------------------------------------------------------------------------
before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_CsrFreeCaptureBuffer = CsrFreeCaptureBuffer;

CsrFreeCaptureBuffer:
00007FFAB20A4980  sub         rsp,28h 
00007FFAB20A4984  cmp         byte ptr [7FFAB21B43ECh],0 
00007FFAB20A498B  jne         CsrFreeCaptureBuffer+1Eh (7FFAB20A499Eh) 

--------------------------------------------------------------------------
after: TrHook(&__imp_CsrFreeCaptureBuffer, hook_CsrFreeCaptureBuffer);
--------------------------------------------------------------------------

CsrFreeCaptureBuffer:
00007FFAB20A4980  jmp         hook_CsrFreeCaptureBuffer 
00007FFAB20A498B  jne         CsrFreeCaptureBuffer+1Eh (7FFAB20A499Eh) 

trampoline:
00007FFA3225F878  sub         rsp,28h 
00007FFA3225F87C  cmp         byte ptr [7FFAB21B43ECh],0 
00007FFA3225F883  jmp         CsrFreeCaptureBuffer+0Bh (7FFAB20A498Bh) 

__imp_CsrFreeCaptureBuffer = trampoline;

////////////////////////////////////////////////////////////////////////////////////////////////////////
// case 7: - Jcc rel8 (2 bytes) extended  to Jcc rel32 (6 bytes) inside trampoline

-------------------------------------------------------------------------
before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_CsrFreeCaptureBuffer = CsrAllocateMessagePointer;

CsrAllocateMessagePointer:
00007FFAB20A46A0  test        edx,edx 
00007FFAB20A46A2  je          CsrAllocateMessagePointer+2Eh (7FFAB20A46CEh) 
00007FFAB20A46A4  mov         rax,qword ptr [rcx+18h] 
00007FFAB20A46A8  mov         qword ptr [r8],rax 

--------------------------------------------------------------------------
after: TrHook(&__imp_CsrAllocateMessagePointer, hook_CsrAllocateMessagePointer);
--------------------------------------------------------------------------
CsrAllocateMessagePointer:
00007FFAB20A46A0  jmp         hook_CsrAllocateMessagePointer 
00007FFAB20A46A8  mov         qword ptr [r8],rax 

trampoline:
00007FFA3225FA38  test        edx,edx 
00007FFA3225FA3A  je          CsrAllocateMessagePointer+2Eh (7FFAB20A46CEh) 
00007FFA3225FA40  mov         rax,qword ptr [rcx+18h] 
00007FFA3225FA44  jmp         CsrAllocateMessagePointer+8 (7FFAB20A46A8h) 

__imp_CsrAllocateMessagePointer = trampoline;

////////////////////////////////////////////////////////////////////////////////////////////////////////
// case 8: function too small ( < 5 bytes )

-------------------------------------------------------------------------
before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_CsrIdentifyAlertableThread = CsrIdentifyAlertableThread;

CsrIdentifyAlertableThread:
00007FFAB20BE480  xor         eax,eax 
00007FFAB20BE482  ret              
00007FFAB20BE483  int         3    
00007FFAB20BE484  int         3    
00007FFAB20BE485  int         3    

--------------------------------------------------------------------------
after: TrHook(&__imp_CsrIdentifyAlertableThread, hook_CsrIdentifyAlertableThread);
--------------------------------------------------------------------------
CsrIdentifyAlertableThread:
00007FFAB20BE480  jmp hook_CsrIdentifyAlertableThread

trampoline:
00007FFA3225F7F8  xor         eax,eax 
00007FFA3225F7FA  ret              

__imp_CsrIdentifyAlertableThread = trampoline;

note - no JMP at the end of trampoline !

////////////////////////////////////////////////////////////////////////////////////////////////////////
// case JMP_rel32: function begin with 5 bytes relative JMP

-------------------------------------------------------------------------
before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_DbgQueryDebugFilterState = DbgQueryDebugFilterState;

DbgQueryDebugFilterState:
00007FFAB211B160  jmp         NtQueryDebugFilterState (7FFAB20D1720h) 

--------------------------------------------------------------------------
after: TrHook(&__imp_DbgQueryDebugFilterState, hook_DbgQueryDebugFilterState);
--------------------------------------------------------------------------

DbgQueryDebugFilterState:
00007FFAB211B160  jmp         hook_DbgQueryDebugFilterState(7FFAB20D1720h) 

__imp_DbgQueryDebugFilterState = NtQueryDebugFilterState;

no trampoline used here ! __imp_DbgQueryDebugFilterState redirected from DbgQueryDebugFilterState to NtQueryDebugFilterState

////////////////////////////////////////////////////////////////////////////////////////////////////////
// case 2: CALL/JMP/Jcc rel32 relocated
-------------------------------------------------------------------------
before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_DbgQueryDebugFilterState = DbgUiConvertStateChangeStructure;

DbgUiConvertStateChangeStructure:
00007FFAB21080E0  xor         r8d,r8d 
00007FFAB21080E3  jmp         DbgUiConvertStateChangeStructureEx+10h (7FFAB2108100h) 

--------------------------------------------------------------------------
after: TrHook(&__imp_DbgUiConvertStateChangeStructure, hook_DbgUiConvertStateChangeStructure);
--------------------------------------------------------------------------

DbgUiConvertStateChangeStructure:
00007FFAB20A46A0  jmp         hook_DbgUiConvertStateChangeStructure 


trampoline:
00007FFA3225F4F8  xor         r8d,r8d 
00007FFA3225F4FB  jmp         DbgUiConvertStateChangeStructureEx+10h (7FFAB2108100h) 

__imp_DbgUiConvertStateChangeStructure = trampoline;

////////////////////////////////////////////////////////////////////////////////////////////////////////
for x86:

-------------------------------------------------------------------------
before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_RtlGetActiveConsoleId = RtlGetActiveConsoleId;

RtlGetActiveConsoleId:
7721FDA0  call        RtlGetCurrentServiceSessionId (771FF310h) 
7721FDA5  test        eax,eax 

--------------------------------------------------------------------------
after: TrHook(&__imp_RtlGetActiveConsoleId, hook_RtlGetActiveConsoleId);
--------------------------------------------------------------------------

RtlGetActiveConsoleId:
7721FDA0  jmp         hook_RtlGetActiveConsoleId
7721FDA5  test        eax,eax 

trampoline:
02902A94  call        RtlGetCurrentServiceSessionId (771FF310h) 
02902A99  jmp         RtlGetActiveConsoleId+5 (7721FDA5h) 

__imp_RtlGetActiveConsoleId = trampoline;

////////////////////////////////////////////////////////////////////////////////////////////////////////
// case 9: Too few instructions !

RtlIsZeroMemory:
7FFB85F5C130   xor         eax,eax
7FFB85F5C132   jmp         00007FFB85F5C143 ↓
7FFB85F5C134   test        rdx,rdx
7FFB85F5C137   je          00007FFB85F5C157 ↓
7FFB85F5C139   cmp         byte ptr [rcx],al
7FFB85F5C13B   jne         00007FFB85F5C171 ↓
7FFB85F5C13D   inc         rcx
7FFB85F5C140   dec         rdx
7FFB85F5C143   test        cl,7
7FFB85F5C146   jne         00007FFB85F5C134 ↑
7FFB85F5C148   jmp         00007FFB85F5C157 ↓
7FFB85F5C14A   cmp         qword ptr [rcx],rax
7FFB85F5C14D   jne         00007FFB85F5C171 ↓
7FFB85F5C14F   add         rcx,8
7FFB85F5C153   sub         rdx,8
7FFB85F5C157   cmp         rdx,8
7FFB85F5C15B   jae         00007FFB85F5C14A ↑
7FFB85F5C15D   test        rdx,rdx
7FFB85F5C160   je          00007FFB85F5C16F ↓
7FFB85F5C162   cmp         byte ptr [rcx],al
7FFB85F5C164   jne         00007FFB85F5C171 ↓
7FFB85F5C166   inc         rcx
7FFB85F5C169   sub         rdx,1
7FFB85F5C16D   jne         00007FFB85F5C162 ↑
7FFB85F5C16F   mov         al,1
7FFB85F5C171   ret

we can not hook such api - only 4 bytes exist
note 
7FFB85F5C146   jne         00007FFB85F5C134 ↑
if we set JMP in [7FFB85F5C130, 7FFB85F5C135) - this will be jmp to instruction body

////////////////////////////////////////////////////////////////////////////////////////////////////////
// skip import jump

-------------------------------------------------------------------------
before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_NtdllDefWindowProc_W = NtdllDefWindowProc_W;

NtdllDefWindowProc_W:
7FFAB20CEAD0   jmp         qword ptr [DefWindowProcW(7FFF55F9A760)]
 
DefWindowProcW
7FFF55F9A760  mov         rax,rsp 
7FFF55F9A763  mov         qword ptr [rax+8],rbx 
7FFF55F9A767  mov         qword ptr [rax+10h],rsi 

--------------------------------------------------------------------------
after: TrHook(&__imp_NtdllDefWindowProc_W, hook_NtdllDefWindowProc_W);
--------------------------------------------------------------------------

NtdllDefWindowProc_W:
7FFAB20CEAD0   jmp         qword ptr [DefWindowProcW(7FFF55F9A760)]

DefWindowProcW
7FFF55F9A760  jmp         hook_NtdllDefWindowProc_W
7FFF55F9A767  mov         qword ptr [rax+10h],rsi

trampoline:
7FFED78555F8  mov         rax,rsp 
7FFED78555FB  mov         qword ptr [rax+8],rbx 
7FFED78555FF  jmp         DefWindowProcW + 7 (7FFF55F9A767h) 

__imp_NtdllDefWindowProc_W = trampoline;

so we set hook on DefWindowProcW instead on NtdllDefWindowProc_W

////////////////////////////////////////////////////////////////////////////////////////////////////////
// case JMP_rel8: function begin with short JMP

-------------------------------------------------------------------------
before:
-------------------------------------------------------------------------
EXTERN_C PVOID __imp_uaw_wcschr = uaw_wcschr;

uaw_wcschr:
7FFF562C6A10  jmp         uaw_wcschr+0Bh (7FFF562C6A1B) 
7FFF562C6A12  test        ax,ax 
7FFF562C6A15  je          uaw_wcschr+18h (7FFF562C6A28) 
7FFF562C6A17  add         rcx,2 
7FFF562C6A1B  movzx       eax,word ptr [rcx] 
7FFF562C6A1E  cmp         ax,dx 
7FFF562C6A21  jne         uaw_wcschr+2 (7FFF562C6A12) 
7FFF562C6A23  mov         rax,rcx 
7FFF562C6A26  ret              
7FFF562C6A27  int         3    
7FFF562C6A28  xor         eax,eax 
7FFF562C6A2A  ret              

--------------------------------------------------------------------------
after: TrHook(&__imp_uaw_wcschr, hook_uaw_wcschr);
--------------------------------------------------------------------------

uaw_wcschr:
7FFF562C6A10  jmp         uaw_wcschr+0Bh (7FFF562C6A1B) 
7FFF562C6A12  test        ax,ax 
7FFF562C6A15  je          uaw_wcschr+18h (7FFF562C6A28) 
7FFF562C6A17  add         rcx,2 
7FFF562C6A1B  jmp         hook_uaw_wcschr
7FFF562C6A21  jne         uaw_wcschr+2 (7FFF562C6A12) 
7FFF562C6A23  mov         rax,rcx 
7FFF562C6A26  ret              
7FFF562C6A27  int         3    
7FFF562C6A28  xor         eax,eax 
7FFF562C6A2A  ret              

trampoline:
FFED786A338  movzx       eax,word ptr [rcx] 
FFED786A33B  cmp         ax,dx 
FFED786A33E  jmp         uaw_wcschr+11h (7FFF562C6A21) 

__imp_uaw_wcschr = trampoline;

usual all such functions ( with short JMP at begin) consist from do-while optimized loop
( uaw_wcschr, SHSearchMapInt, FixSlashesAndColonW)

problem here - that hook function can be recursive called in loop

example of uaw_wcschr hook:


PUWSTR
__cdecl
hook_uaw_wcschr(
		   _In_ PCUWSTR String,
		   _In_ WCHAR   Character
		   )
{
	DbgPrint("%p: %p> uaw_wcschr(\"%S\", '%c')...\n", _AddressOfReturnAddress(), _ReturnAddress(), String, Character);
	PUWSTR pw = uaw_wcschr(String, Character);
	DbgPrint("%p: %p> uaw_wcschr(\"%S\", '%c') = \"%S\"\n", _AddressOfReturnAddress(), _ReturnAddress(), String, Character, pw);
	return pw;
}

	TrInit();
	TrHook(&__imp_uaw_wcschr, hook_uaw_wcschr);
	uaw_wcschr(L"123*567", '*'); 

and debug output:

000000459910F978: 00007FF6E5FEFCAB> uaw_wcschr("23*567", '*')...
000000459910F928: 00007FF6E5FF086E> uaw_wcschr("3*567", '*')...
000000459910F8D8: 00007FF6E5FF086E> uaw_wcschr("*567", '*')...
000000459910F8D8: 00007FF6E5FF086E> uaw_wcschr("*567", '*') = "*567"
000000459910F928: 00007FF6E5FF086E> uaw_wcschr("3*567", '*') = "*567"
000000459910F978: 00007FF6E5FEFCAB> uaw_wcschr("23*567", '*') = "*567"

////////////////////////////////////////////////////////////////////////////////////////////////////////
// "micro" jmp

case when JMP/Jcc/LOOP/JRCX point to first 5 bytes offunction ( where JMP must be placed )
probably only hypothetical case, but for correct handle, require many extra code.

before:

someapi:
7FF64B5096CF  jrcxz       someapi+4 (7FF64B5096D3) 
7FF64B5096D1  jnp         someapi+6 (7FF64B5096D5) 
7FF64B5096D3  loop        someapi (7FF64B5096CF) 
7FF64B5096D5  ...  

after:

someapi:
7FF64B5096CF  jmp         NT::hook_someapi (7FF64B510F14h) 
7FF64B5096D5  ...              

trampoline:
7FF5CB53FFB8  jrcxz       7FF5CB53FFC0 
7FF5CB53FFBA  jnp         someapi+6 (7FF64B5096D5) 
7FF5CB53FFC0  loop        7FF5CB53FFB8 
7FF5CB53FFC2  jmp         someapi+6 (7FF64B5096D5) 
```

*****************************************************************************************************

at the begin of hooked api, we set of direct JMP to hook if this is possible or JMP to indirect JMP [hook_someapi] inside trampoline 
( if more 2GB distance between someapi and hook_someapi )

so, after hook will be or
```
someapi:
	jmp hook_someapi ; JMP rel32
```	
or 

```
someapi:
	jmp tramp ; JMP rel32

tramp:
	jmp [hook_someapi] ; JMP [m64]
```	
	
at the end of trampoline usually will be relative JMP to the code after JMP at function body
except case 8 - when hooked function is too small ( ret or JMP instruction already in tramoline )
