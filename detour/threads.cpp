#include "StdAfx.h"

_NT_BEGIN
#include "threads.h"

#ifdef _X86_
#define __IMP(x) _imp__ ## x
#pragma comment(linker, "/include:__imp__Dbg_Print")
#else
#define __IMP(x) __imp_ ## x
#pragma comment(linker, "/include:__imp_Dbg_Print")
#endif

EXTERN_C
NTSYSAPI
NTSTATUS NTAPI NtGetNextThread(
							   _In_ HANDLE ProcessHandle,
							   _In_ HANDLE ThreadHandle,
							   _In_ ACCESS_MASK DesiredAccess,
							   _In_ ULONG HandleAttributes,
							   _In_ ULONG Flags,
							   _Out_ PHANDLE NewThreadHandle
							   );

void __cdecl Nop_Print(_In_z_ _Printf_format_string_ PCSTR , ...)
{
}

EXTERN_C PVOID __IMP(Dbg_Print) = Nop_Print;

struct ThreadInfo : CONTEXT 
{
	HANDLE hThread = 0;
	ThreadInfo* next = 0;
	HANDLE UniqueThread; // for debug only

	~ThreadInfo()
	{
		Dbg_Print("%s<%p>(%p)\n", __FUNCTION__, this, UniqueThread);
	}

	ThreadInfo(HANDLE UniqueThread) : UniqueThread(UniqueThread)
	{
		RtlZeroMemory(static_cast<CONTEXT*>(this), sizeof(CONTEXT));
		ContextFlags = CONTEXT_CONTROL;
		Dbg_Print("%s<%p>(%p)\n", __FUNCTION__, this, UniqueThread);
	}
};

void ResumeAndFree(_In_ ThreadInfo* next)
{
	if (ThreadInfo* pti = next)
	{
		do 
		{
			next = pti->next;

			if (HANDLE hThread = pti->hThread)
			{
				ZwResumeThread(hThread, 0);
				NtClose(hThread);
			}

			delete pti;

		} while (pti = next);
	}
}

NTSTATUS SuspendAll(_Out_ ThreadInfo** ppti)
{
	ThreadInfo* pti = 0;
	HANDLE ThreadHandle = 0, hThread;
	NTSTATUS status;
	BOOL bClose = FALSE;

	HANDLE UniqueThread = (HANDLE)GetCurrentThreadId();

loop:
	status = NtGetNextThread(NtCurrentProcess(), ThreadHandle, 
		THREAD_QUERY_LIMITED_INFORMATION|THREAD_SUSPEND_RESUME|THREAD_GET_CONTEXT|THREAD_SET_CONTEXT, 
		0, 0, &hThread);

	if (bClose)
	{
		NtClose(ThreadHandle);
		bClose = FALSE;
	}

	if (0 <= status)
	{
		ThreadHandle = hThread;

		THREAD_BASIC_INFORMATION tbi;

		if (0 <= (status = ZwQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), 0)))
		{
			if (tbi.ClientId.UniqueThread == UniqueThread)
			{
				bClose = TRUE;
				goto loop;
			}

			status = STATUS_NO_MEMORY;

			if (ThreadInfo* next = new ThreadInfo(tbi.ClientId.UniqueThread))
			{
				if (0 <= (status = ZwSuspendThread(hThread, 0)))
				{
					if (0 <= (status = ZwGetContextThread(hThread, next)))
					{
						next->next = pti;
						pti = next;
						next->hThread = hThread;
						goto loop;
					}

					ZwResumeThread(hThread, 0);
				}

				delete next;
			}
		}

		NtClose(hThread);
	}

	switch (status)
	{
	case STATUS_NO_MORE_ENTRIES:
	case STATUS_SUCCESS:
		*ppti = pti;
		return STATUS_SUCCESS;
	}

	ResumeAndFree(pti);

	*ppti = 0;
	return status;
}

#if defined(_M_IX86)
#define Xip Eip
#elif defined (_M_X64)
#define Xip Rip
#else
#error
#endif

#include "threads.h"

BOOLEAN MovePc(_In_ ThreadInfo* pti, _In_ ULONG_PTR PcFrom, _In_ ULONG_PTR PcTo, _In_ ULONG cb, _In_ DTA* Lens)
{
	BOOLEAN fOk = FALSE;

	if (pti)
	{
		do 
		{
			SIZE_T s = pti->Xip - PcFrom;

			if (s < cb)
			{
				pti->Xip = PcTo + s;

				ULONG ofs;

				if (ofs = Lens->ofs1)
				{
					if (ofs <= s)
					{
						pti->Xip += Lens->add1;
					}
				}

				if (ofs = Lens->ofs2)
				{
					if (ofs <= s)
					{
						pti->Xip += Lens->add2;
					}
				}

				Dbg_Print("MovePc: %p -> %p\n", PcFrom + s, pti->Xip);

				if (0 > ZwSetContextThread(pti->hThread, pti))
				{
					fOk = FALSE;
				}
			}

		} while (pti = pti->next);
	}

	return fOk;
}

_NT_END