#pragma once

extern "C" {
extern IMAGE_DOS_HEADER __ImageBase;
}

typedef int (__cdecl * QSORTFN) (const void *, const void *);
typedef int (__cdecl * QSORTFN_S)(void *, const void *, const void *);

#ifndef _NTDRIVER_

NTDLL_(LONGLONG)
RtlInterlockedCompareExchange64 (
								 LONGLONG volatile *Destination,
								 LONGLONG Exchange,
								 LONGLONG Comperand
							  );

#define InterlockedPopEntrySList(Head) RtlInterlockedPopEntrySList(Head)
#define InterlockedPushEntrySList(Head, Entry) RtlInterlockedPushEntrySList(Head, Entry)
#define InterlockedFlushSList(Head) RtlInterlockedFlushSList(Head)
#define QueryDepthSList(Head) RtlQueryDepthSList(Head)
#define FirstEntrySList(Head) RtlFirstEntrySList(Head)

#ifndef _WIN64
#define InterlockedCompareExchange64(Destination, ExChange, Comperand) RtlInterlockedCompareExchange64(Destination, ExChange, Comperand)
#endif

#endif//_NTDRIVER_

#ifndef _WIN64
#define InterlockedCompareExchangePointer(Destination, ExChange, Comperand) \
	(PVOID)(LONG_PTR)InterlockedCompareExchange((PLONG)(Destination), (LONG)(LONG_PTR)(ExChange), (LONG)(LONG_PTR)(Comperand))

#define InterlockedExchangePointer(Destination, ExChange) \
	(PVOID)(LONG_PTR)InterlockedExchange((PLONG)(Destination), (LONG)(LONG_PTR)(ExChange))
#endif

#if 0//ndef _WIN64
#ifdef SetWindowLongPtrW
#undef SetWindowLongPtrW
#endif
#define SetWindowLongPtrW(hwnd, i, val)  ((LPARAM)SetWindowLongW(hwnd, i, (LONG)(LPARAM)(val)))
#ifdef GetWindowLongPtrW
#undef GetWindowLongPtrW
#endif
#define GetWindowLongPtrW(hwnd, i)  ((LPARAM)GetWindowLongW(hwnd, i))
#endif

#ifdef _WIN64
#define GetArbitraryUserPointer() (PVOID)__readgsqword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer))
#define SetArbitraryUserPointer(p) __writegsqword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer), (DWORD_PTR)(p))
#else
#define GetArbitraryUserPointer() (PVOID)__readfsdword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer))
#define SetArbitraryUserPointer(p) __writefsdword(FIELD_OFFSET(NT_TIB, ArbitraryUserPointer), (DWORD_PTR)(p))
#endif

//////////////////////////////////////////////////////////////////////////

template <typename T>
T ToError(ULONG& dwError, T v)
{
	dwError = v ? NOERROR : GetLastError();
	return v;
}

#define GLE(x) ToError(dwError, x)

template <typename T>
T ToHr(HRESULT& hr, T v)
{
	hr = v ? S_OK : HRESULT_FROM_WIN32(GetLastError());
	return v;
}

#define GLH(x) ToHr(hr, x)

inline ULONG BOOL_TO_ERROR(BOOL f)
{
	return f ? NOERROR : GetLastError();
}

inline HANDLE fixH(HANDLE hFile)
{
	return hFile == INVALID_HANDLE_VALUE ? 0 : hFile;
}

#ifdef _malloca
#undef _malloca
#endif
#ifdef _freea
#undef _freea
#endif

#define _malloca(size) ((size) < _ALLOCA_S_THRESHOLD ? alloca(size) : new BYTE[size])

inline void _freea(PVOID pv)
{
	PNT_TIB tib = (PNT_TIB)NtCurrentTeb();
	if (pv < tib->StackLimit || tib->StackBase <= pv) delete [] pv;
}

inline HRESULT GetLastHr(ULONG dwError = GetLastError())
{
	return dwError ? HRESULT_FROM_WIN32(dwError) : S_OK;
}

inline HRESULT GetLastHr(BOOL fOk)
{
	return fOk ? S_OK : HRESULT_FROM_WIN32(GetLastError());
}

inline HRESULT VtoHr(ULONG_PTR r)
{
	return r ? S_OK : GetLastHr();
}

#define PtoHr(r) VtoHr((ULONG_PTR)(r))

////////////////////////////////////////////////////////////////
// CID

struct CID : CLIENT_ID
{
	CID(HANDLE _UniqueProcess, HANDLE _UniqueThread = 0)
	{
		UniqueThread = _UniqueThread;
		UniqueProcess = _UniqueProcess;
	}
};

///////////////////////////////////////////////////////////////
// CUnicodeString

class CUnicodeString : public UNICODE_STRING
{
public:
	CUnicodeString(PCWSTR String)
	{
		RtlInitUnicodeString(this,String);
	}
};

///////////////////////////////////////////////////////////////
// CObjectAttributes

struct CObjectAttributes : public OBJECT_ATTRIBUTES
{
	CObjectAttributes(LPCWSTR _ObjectName,
		HANDLE _RootDirectory = 0,
		ULONG _Attributes = OBJ_CASE_INSENSITIVE,
		PVOID _SecurityDescriptor = 0,
		PVOID _SecurityQualityOfService = 0
		)
	{
		Length = sizeof OBJECT_ATTRIBUTES;
		RtlInitUnicodeString(ObjectName = &mus,_ObjectName);
		RootDirectory = _RootDirectory;
		Attributes = _Attributes;
		SecurityDescriptor = _SecurityDescriptor;
		SecurityQualityOfService = _SecurityQualityOfService;
	}
	CObjectAttributes(PCUNICODE_STRING _ObjectName,
		HANDLE _RootDirectory = 0,
		ULONG _Attributes = OBJ_CASE_INSENSITIVE,
		PVOID _SecurityDescriptor = 0,
		PVOID _SecurityQualityOfService = 0
		)
	{
		Length = sizeof OBJECT_ATTRIBUTES;
		ObjectName = (PUNICODE_STRING)_ObjectName;
		RootDirectory = _RootDirectory;
		Attributes = _Attributes;
		SecurityDescriptor = _SecurityDescriptor;
		SecurityQualityOfService = _SecurityQualityOfService;
	}
private:
	UNICODE_STRING mus;
};

#include "mini_yvals.h"

#define _makeachar(x) #@x
#define makeachar(x) _makeachar(x)
#define _makewchar(x) L## #@x
#define makewchar(x) _makewchar(x)
#define echo(x) x
#define label(x) echo(x)##__LINE__
#define showmacro(x) __pragma(message(__FILE__ _CRT_STRINGIZE((__LINE__): \nmacro\t)#x" expand to\n" _CRT_STRINGIZE(x)))

#define IID_PPV(pItf) __uuidof(*pItf),(void**)&pItf

#define RTL_CONSTANT_STRINGA(s) { sizeof( s ) - sizeof( (s)[0] ), sizeof( s ), const_cast<PSTR>(s) }
#define RTL_CONSTANT_STRINGW_(s) { sizeof( s ) - sizeof( (s)[0] ), sizeof( s ), const_cast<PWSTR>(s) }
#define RTL_CONSTANT_STRINGW(s) RTL_CONSTANT_STRINGW_(echo(L)echo(s))

#define STATIC_UNICODE_STRING(name, str) \
static const WCHAR label(__)[] = echo(L)str;\
static const UNICODE_STRING name = RTL_CONSTANT_STRINGW_(label(__))

#define STATIC_ANSI_STRING(name, str) \
static const CHAR label(__)[] = str;\
static const ANSI_STRING name = RTL_CONSTANT_STRINGA(label(__))

#define STATIC_ASTRING(name, str) static const CHAR name[] = str
#define STATIC_WSTRING(name, str) static const WCHAR name[] = echo(L)str

#define STATIC_UNICODE_STRING_(name) STATIC_UNICODE_STRING(name, #name)
#define STATIC_WSTRING_(name) STATIC_WSTRING(name, #name)
#define STATIC_ANSI_STRING_(name) STATIC_ANSI_STRING(name, #name)
#define STATIC_ASTRING_(name) STATIC_ASTRING(name, #name)

#define STATIC_OBJECT_ATTRIBUTES(oa, name)\
	STATIC_UNICODE_STRING(label(m), name);\
	static OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(&label(m)), OBJ_CASE_INSENSITIVE }

#define STATIC_OBJECT_ATTRIBUTES_EX(oa, name, a, sd, sqs)\
	STATIC_UNICODE_STRING(label(m), name);\
	static OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(&label(m)), a, sd, sqs }


#define BEGIN_PRIVILEGES(name, n) static const union { TOKEN_PRIVILEGES name;\
struct { ULONG PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[n];} label(_) = { n, {

#define LAA(se) {{se}, SE_PRIVILEGE_ENABLED }
#define LAA_D(se) {{se} }

#define END_PRIVILEGES }};};

#pragma warning(default : 4005)
