#pragma once

#define NTDLL__(type)	extern "C" __declspec(dllimport) type 
#define NTDLL_(type)	NTDLL__(type) CALLBACK
#define NTDLL			NTDLL_(NTSTATUS)
#define NTDLL_V NTDLL_(void)

#include "ntlpcapi.h"
#include "ntdbg.h"

typedef int (__cdecl *QSORTFN)(const void*, const void*);

NTDLL_(_PEB*) RtlGetCurrentPeb();

NTDLL CsrNewThread();

NTDLL ZwImpersonateClientOfPort(HANDLE hPort, PPORT_MESSAGE pm);

NTDLL RtlGetLastNtStatus();

NTDLL RtlExitUserThread(DWORD dwExitCode);

NTDLL ZwSuspendProcess(HANDLE hProcess);
NTDLL ZwResumeProcess(HANDLE hProcess);

NTDLL
ZwOpenThread
(
	OUT PHANDLE ThreadHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL
	);

NTDLL
ZwWaitForMultipleObjects
(
	IN ULONG HandleCount,
	IN PHANDLE Handles,
	IN WAIT_TYPE WaitTYpe,
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Timeout OPTIONAL
	);

NTDLL
ZwNotifyChangeDirectoryFile
(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	PFILE_NOTIFY_INFORMATION Buffer,
	ULONG BufferLength,
	ULONG NotifyFilter,
	BOOLEAN WatchSubtree
	);

NTDLL ZwQueryEvent(HANDLE EventHandle,
				   EVENT_INFORMATION_CLASS EventInformationClass,
				   PVOID EventInformation,
				   ULONG EventInformationLength,
				   PULONG ReturnLength);


NTDLL 
ZwExtendSection
(
	HANDLE SectionHaqndle,
	PLARGE_INTEGER SectionSize
	);

NTDLL 
ZwImpersonateThread
(
	HANDLE SourceThreadHandle,
	HANDLE TargetThreadHandle,
	PSECURITY_QUALITY_OF_SERVICE Security
	);

NTDLL RtlQueryEnvironmentVariable_U(IN PVOID  Environment OPTIONAL,
									IN PCUNICODE_STRING      VariableName,
									OUT PUNICODE_STRING     VariableValue );


typedef VOID (NTAPI * APC_CALLBACK_FUNCTION)(
						   NTSTATUS status,
						   ULONG_PTR Information,
						   PVOID Context
						   );

NTDLL RtlSetIoCompletionCallback(HANDLE FileHandle, APC_CALLBACK_FUNCTION Function, ULONG Flags);

NTDLL_(DWORD) RtlComputeCrc32(DWORD crc, LPCVOID buf, DWORD cb);

NTDLL ZwCreateMailslotFile
(
 OUT PHANDLE             MailslotFileHandle,
 IN ACCESS_MASK          DesiredAccess,
 IN POBJECT_ATTRIBUTES   ObjectAttributes,
 OUT PIO_STATUS_BLOCK    IoStatusBlock,
 IN ULONG                CreateOptions,
 IN ULONG                MailslotQuota,
 IN ULONG                MaxMessageSize,
 IN PLARGE_INTEGER       ReadTimeOut 
 );

NTDLL
ZwCreateNamedPipeFile
(
	PHANDLE FileHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG ShareAccess,
	ULONG CreateDisposition,
	ULONG CreateOptions,
	ULONG NamedPipeType,//FILE_PIPE_*_TYPE 0,1
	ULONG ReadMode,//FILE_PIPE_*_MODE 0,1
	ULONG CompletionMode,//FILE_PIPE_*_OPERATION 0,1
	ULONG MaxInstances,
	ULONG InBufferSize,
	ULONG OutBufferSize,
	PLARGE_INTEGER DefaultTimeout
	);

NTDLL 
ZwSetDebugFilterState
(
	ULONG Index,
	ULONG Mask,
	BOOLEAN bSet
	);

NTDLL_(BOOLEAN)
ZwQueryDebugFilterState
(
	ULONG Index,
	ULONG Mask
	);

NTDLL RtlFindMessage
(
	HMODULE hModule,
	LPCWSTR Type,
	LANGID LangId,
	ULONG MessageId,
	PMESSAGE_RESOURCE_ENTRY& MessageEntry
	);

NTDLL
ZwQueryDefaultUILanguage(LANGID& LangId);

NTDLL NtQuerySystemTime(PLARGE_INTEGER time);
NTDLL RtlSystemTimeToLocalTime(const LARGE_INTEGER* SystemTime, PLARGE_INTEGER LocalTime);
NTDLL RtlLocalTimeToSystemTime(const LARGE_INTEGER* LocalTime, PLARGE_INTEGER SystemTime);

NTDLL RtlAcquirePebLock();

NTDLL RtlReleasePebLock();

NTDLL_(VOID) CsrProbeForWrite 
(
	PVOID Address,
	SIZE_T Length,
	ULONG Alignment
	);

NTDLL_(VOID) CsrProbeForRead 
(
	PVOID Address,
	SIZE_T Length,
	ULONG Alignment
	);

NTDLL_(void*) PsGetThreadWin32Thread(PKTHREAD Thread);
NTDLL_(void) PsSetThreadWin32Thread(PKTHREAD Thread, void *Win32Thread, void *Win32Thread0);

NTDLL_(LPVOID) PsGetCurrentThreadStackLimit();
NTDLL_(LPVOID) PsGetCurrentThreadStackBase();	

NTDLL_(HANDLE) PsGetProcessInheritedFromUniqueProcessId(PEPROCESS);

NTDLL_(LPCSTR) PsGetProcessImageFileName(PEPROCESS Process);

NTDLL_(PPEB) PsGetProcessPeb(PEPROCESS Process);
NTDLL_(_TEB*) PsGetThreadTeb(IN PETHREAD Thread);

NTDLL ZwCreateProfile
(
	PHANDLE phProfile,
	HANDLE hProcess,
	LPVOID Base,
	ULONG Size,
	ULONG shift,
	PULONG Buffer,
	ULONG BufferLength,
	KPROFILE_SOURCE Source,
	KAFFINITY ProcessorMask
	);

NTDLL ZwSetIntervalProfile(ULONG Interval, KPROFILE_SOURCE Source);
NTDLL ZwQueryIntervalProfile(KPROFILE_SOURCE Source, PULONG Interval);
NTDLL ZwStartProfile(HANDLE hProfile);
NTDLL ZwStopProfile(HANDLE hProfile);

NTDLL RtlRunDecodeUnicodeString(BYTE, PUNICODE_STRING);
NTDLL RtlRunEncodeUnicodeString(LPBYTE, PUNICODE_STRING);

NTDLL ObSetSecurityObjectByPointer (
							  IN PVOID Object,
							  IN SECURITY_INFORMATION SecurityInformation,
							  IN PSECURITY_DESCRIPTOR SecurityDescriptor
							  );

NTDLL
PsGetContextThread
(
	PKTHREAD Thread,
	PCONTEXT Context,
	MODE PreviousMode
	);

NTDLL
PsSetContextThread
(
	PKTHREAD Thread,
	PCONTEXT Context,
	MODE PreviousMode
	);

NTDLL_(void)
KeSetSystemAffinityThread
(
	KAFFINITY AffinityMask
);

NTDLL_(void)
KeRevertToUserAffinityThread
(
);

NTDLL_(PIMAGE_NT_HEADERS)
RtlImageNtHeader 
(
	PVOID Base
	);

NTDLL_(PVOID)
RtlImageDirectoryEntryToData
(
	PVOID Base,
	BOOLEAN MappedAsImage,
	USHORT DirectoryEntry,
	PULONG Size
	);

NTDLL_(PIMAGE_SECTION_HEADER)
RtlImageRvaToSection
(
	PIMAGE_NT_HEADERS NtHeaders,
	LPVOID Base,
	ULONG Rva
	);

NTDLL_(LPVOID) RtlAddressInSectionTable
(
	PIMAGE_NT_HEADERS NtHeaders,
	LPVOID Base,
	ULONG Rva
	);

NTDLL DbgUserBreakPoint
(
);

NTDLL
ZwCreateIoCompletion
(
	PHANDLE hIocp,
	ACCESS_MASK DesiredAcces,
	POBJECT_ATTRIBUTES oa,
	ULONG NumberOfConcurrentThreads
	);

NTDLL
ZwOpenIoCompletion
(
	PHANDLE hIocp,
	ACCESS_MASK DesiredAcces,
	POBJECT_ATTRIBUTES oa
	);

NTDLL
ZwSetIoCompletion
(
	HANDLE hIocp,
	PVOID Key,
	PVOID ApcContext,
	NTSTATUS Status,
	ULONG_PTR Information
	);

NTDLL
ZwRemoveIoCompletion
(
	HANDLE hIocp,
	PVOID* Key,
	PVOID* ApcContext,
	PIO_STATUS_BLOCK iosb,
	PLARGE_INTEGER timeout
	);

NTDLL
ZwNotifyChangeKey
(
	HANDLE hKey,
	HANDLE hEvent,
	PIO_APC_ROUTINE pfnApc,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG NotifyFilter,
	BOOLEAN WatchSubtree,
	PVOID Buffer = 0,
	ULONG BufferLength = 0,
	BOOLEAN Asynchronous = TRUE
	);

NTDLL
ZwQueryInformationThread
(
	HANDLE hThread,
	THREADINFOCLASS InformationClass,
	PVOID Information,
	ULONG InformationLength,
	PULONG ReturnLength
);

NTDLL
RtlFreeUserThreadStack
(
	HANDLE hProcess,
	HANDLE hThread
);

NTDLL_(PVOID) RtlAddVectoredExceptionHandler( __in ULONG First, __in PVECTORED_EXCEPTION_HANDLER Handler );
NTDLL_(ULONG) RtlRemoveVectoredExceptionHandler( __in PVOID Handle );

NTDLL
ZwRaiseException
(
	PEXCEPTION_RECORD ExceptionRecord,
	PCONTEXT Context,
	BOOLEAN SearchFrames
);

NTDLL
ZwRegisterThreadTerminatePort
(
	HANDLE hPort
);

NTDLL
ZwCreateMutant
(
	PHANDLE MutantHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	BOOLEAN InitialOwner
);

NTDLL
ZwOpenMutant
(
	PHANDLE MutantHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes
);

NTDLL
ZwReleaseMutant(
				IN HANDLE hMutant,
				OUT OPTIONAL PULONG bWasSignalled
				);

NTDLL
ZwCreateSymbolicLinkObject
(
	PHANDLE	SymbolicLinkHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	const UNICODE_STRING* TargetName
);

NTDLL NtWriteFileGather (
						 __in HANDLE FileHandle,
						 __in_opt HANDLE Event,
						 __in_opt PIO_APC_ROUTINE ApcRoutine,
						 __in_opt PVOID ApcContext,
						 __out PIO_STATUS_BLOCK IoStatusBlock,
						 __in PFILE_SEGMENT_ELEMENT SegmentArray,
						 __in ULONG Length,
						 __in_opt PLARGE_INTEGER ByteOffset,
						 __in_opt PULONG Key
						 );

NTDLL ZwWriteFileGather (
						 __in HANDLE FileHandle,
						 __in_opt HANDLE Event,
						 __in_opt PIO_APC_ROUTINE ApcRoutine,
						 __in_opt PVOID ApcContext,
						 __out PIO_STATUS_BLOCK IoStatusBlock,
						 __in PFILE_SEGMENT_ELEMENT SegmentArray,
						 __in ULONG Length,
						 __in_opt PLARGE_INTEGER ByteOffset,
						 __in_opt PULONG Key
						 );

NTDLL NtReadFileScatter(
						_In_ HANDLE FileHandle,
						_In_opt_ HANDLE Event,
						_In_opt_ PIO_APC_ROUTINE ApcRoutine,
						_In_opt_ PVOID ApcContext,
						_Out_ PIO_STATUS_BLOCK IoStatusBlock,
						_In_ PFILE_SEGMENT_ELEMENT SegmentArray,
						_In_ ULONG Length,
						_In_opt_ PLARGE_INTEGER ByteOffset,
						_In_opt_ PULONG Key
				  );

NTDLL ZwReadFileScatter(
						_In_ HANDLE FileHandle,
						_In_opt_ HANDLE Event,
						_In_opt_ PIO_APC_ROUTINE ApcRoutine,
						_In_opt_ PVOID ApcContext,
						_Out_ PIO_STATUS_BLOCK IoStatusBlock,
						_In_ PFILE_SEGMENT_ELEMENT SegmentArray,
						_In_ ULONG Length,
						_In_opt_ PLARGE_INTEGER ByteOffset,
						_In_opt_ PULONG Key
				  );


NTDLL
RtlAdjustPrivilege
(
	ULONG	PrivilegeValue,
	BOOLEAN Enable,
	BOOLEAN ToThreadOnly,
	PBOOLEAN PreviousEnable
);

enum SEMAPHORE_INFORMATION_CLASS { SemaphoreBasicInformation };

struct SEMAPHORE_BASIC_INFORMATION
{
	LONG CurrentCount;
	LONG MaximumCount;
};

NTDLL ZwOpenSemaphore(PHANDLE SemaphoreHandle,
					  ACCESS_MASK DesiredAcces,
					  POBJECT_ATTRIBUTES ObjectAttributes 
					  );

NTDLL ZwCreateSemaphore(PHANDLE SemaphoreHandle,
						ACCESS_MASK DesiredAccess,
						POBJECT_ATTRIBUTES ObjectAttributes,
						LONG InitialCount,
						LONG MaximumCount 
					 );

NTDLL ZwQuerySemaphore(HANDLE SemaphoreHandle,
					   SEMAPHORE_INFORMATION_CLASS SemaphoreInformationClass,
					   PVOID SemaphoreInformation,
					   ULONG Length,
					   PULONG ReturnLength 
					   );

NTDLL ZwReleaseSemaphore(HANDLE hSemaphore, LONG lReleaseCount, LPLONG lpPreviousCount );

NTDLL
ZwCreateToken
(
	PHANDLE	hToken,
	ACCESS_MASK DEsiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	TOKEN_TYPE Type,
	PLUID AutenticId,
	PLARGE_INTEGER ExpirationTime,
	PTOKEN_USER User,
	PTOKEN_GROUPS Groups,
	PTOKEN_PRIVILEGES Provileges,
	PTOKEN_OWNER Owner,
	PTOKEN_PRIMARY_GROUP PrimaryGroup,
	PTOKEN_DEFAULT_DACL DefaultDacl,
	PTOKEN_SOURCE Source 
);

NTDLL ZwSetInformationToken(
							HANDLE hToken, 
							TOKEN_INFORMATION_CLASS TokenInformationClass, 
							PVOID TokenInformation, 
							DWORD TokenInformationLength
							);

NTDLL 
ZwQueryAttributesFile
(POBJECT_ATTRIBUTES poa, PFILE_BASIC_INFORMATION pfbi);

NTDLL
ZwOpenProcessToken
(
	HANDLE hProcess,
	ULONG  DesiredAccesss,
	PHANDLE hToken
);

NTDLL
ZwImpersonateAnonymousToken
(
	IN HANDLE hThread
);

NTDLL
ZwDuplicateToken
(
	IN HANDLE ExistingTokenHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN BOOLEAN EffectiveOnly,
	IN TOKEN_TYPE TokenType,
	OUT PHANDLE NewTokenHandle
);

NTDLL 
ZwOpenEvent
(
	OUT	PHANDLE hEvent,
	IN  ULONG Access,
	IN  POBJECT_ATTRIBUTES ObjectAttributes
);

NTDLL 
ZwCreateEventPair
(
	OUT	PHANDLE EventPair,
	IN  ULONG Access,
	IN  POBJECT_ATTRIBUTES ObjectAttributes
);

NTDLL 
ZwOpenEventPair
(
	OUT	PHANDLE EventPair,
	IN  ULONG Access,
	IN  POBJECT_ATTRIBUTES ObjectAttributes
);

NTDLL ZwSetHighWaitLowEventPair(HANDLE);
NTDLL ZwSetLowWaitHighEventPair(HANDLE);

NTDLL ZwSetHighEventPair(HANDLE);
NTDLL ZwSetLowEventPair(HANDLE);

NTDLL ZwWaitLowEventPair(HANDLE);
NTDLL ZwWaitHighEventPair(HANDLE);

NTDLL ZwAlertResumeThread(HANDLE hThread, PULONG SuspendCount);

NTDLL ZwResumeThread(HANDLE hThread, PULONG SuspendCount);
NTDLL ZwSuspendThread(HANDLE hThread, PULONG SuspendCount);

NTDLL
ExRaiseHardError
(
	NTSTATUS Status,
	ULONG NumberOfArguments,
	ULONG StringArgumentsMask,
	PULONG_PTR Arguments,
	HARDERROR_RESPONSE_OPTION ResponseOption,
	PHARDERROR_RESPONSE Response
	);

NTDLL
ZwRaiseHardError
(
	NTSTATUS Status,
	ULONG NumberOfArguments,
	ULONG StringArgumentsMask,
	PULONG_PTR Arguments,
	HARDERROR_RESPONSE_OPTION ResponseOption,
	PHARDERROR_RESPONSE Response
);

NTDLL_(PEPROCESS) PsGetThreadProcess(PKTHREAD);
NTDLL_(BOOLEAN) PsIsProcessBeingDebugged(PEPROCESS);

NTDLL ZwQueueApcThread(HANDLE hThread, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2);

NTDLL RtlQueueApcWow64Thread(HANDLE hThread, PKNORMAL_ROUTINE ApcRoutine, PVOID ApcContext, PVOID Argument1, PVOID Argument2);

NTDLL_(void) RtlGetNtVersionNumbers(PULONG Major, PULONG Minor, PULONG Build);

NTDLL
ZwQuerySystemInformation
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTDLL
NtQuerySystemInformation
(
 IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
 OUT PVOID SystemInformation,
 IN ULONG SystemInformationLength,
 OUT PULONG ReturnLength OPTIONAL
 );

NTDLL
ZwSetSystemInformation
(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength
);

NTDLL
ZwQueryInformationProcess
(
	IN HANDLE ProcessHandle,
	IN  PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL
);

NTDLL
ZwSetInformationProcess
(
 IN HANDLE ProcessHandle,
 IN  PROCESSINFOCLASS ProcessInformationClass,
 IN PVOID ProcessInformation,
 IN ULONG ProcessInformationLength
 );

NTDLL
NtSetInformationProcess
(
 IN HANDLE ProcessHandle,
 IN  PROCESSINFOCLASS ProcessInformationClass,
 IN PVOID ProcessInformation,
 IN ULONG ProcessInformationLength
 );

NTDLL
NtQueryInformationProcess
(
 IN HANDLE ProcessHandle,
 IN  PROCESSINFOCLASS ProcessInformationClass,
 OUT PVOID ProcessInformation,
 IN ULONG ProcessInformationLength,
 OUT PULONG ReturnLength OPTIONAL
 );

NTDLL
ZwCreateProcess
(
	OUT PHANDLE ProcessHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE InheritFromProcessHandle,
	IN BOOLEAN InheritHandles,
	IN HANDLE SectionHandle OPTIONAL,
	IN HANDLE DebugPort OPTIONAL,
	IN HANDLE ExceptionPort OPTIONAL
);

#define CREATEPROCESS_BREAKAWAY_FROM_JOB 1
#define CREATEPROCESS_DEBUG_ONLY_THIS_PROCESS 2
#define CREATEPROCESS_INHERIT_HANDLES 4

NTDLL
ZwCreateProcessEx
(
	PHANDLE ProcessHandle, 
	ULONG DesiredAccess, 
	POBJECT_ATTRIBUTES ObjectAttributes, 
	HANDLE InheritFromProcessHandle, 
	ULONG Flags, 
	HANDLE SectionHandle, 
	HANDLE DebugPort, 
	HANDLE ExceptionPort,
	ULONG
	);

NTDLL
ZwOpenProcess
(
	OUT PHANDLE ProcessHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID Cid OPTIONAL
);

NTDLL
ZwTerminateProcess
(
	IN HANDLE ProcessHandle OPTIONAL,
	IN NTSTATUS ExitStatus
);

NTDLL
ZwSetContextThread
(
	IN HANDLE ThreadHandle,
	IN _CONTEXT* Context
);

NTDLL
ZwGetContextThread
(
	IN HANDLE ThreadHandle,
	IN OUT _CONTEXT* Context
);

NTDLL
ZwContinue
(
	IN PCONTEXT Context,
	IN BOOLEAN TestAlert
);

NTDLL
KeUserModeCallback
(
	IN ULONG RoutineIndex,
	IN PVOID Argument,
	IN ULONG ArgumentLength,
	OUT PVOID* Result,
	OUT PULONG ResultLenght
);

NTDLL
KiUserCallbackDispatcher
(
	IN ULONG RoutineIndex,
	IN PVOID Argument,
	IN ULONG ArgumentLength
);

NTDLL
KiUserApcDispatcher
(
	PKNORMAL_ROUTINE NormalRoutine,
	PVOID ApcContext,
	PVOID Argument1,
	PVOID Argument2
#ifdef _WIN64
	,PCONTEXT Context
#endif
);

NTDLL
KiUserExceptionDispatcher
(
	PEXCEPTION_RECORD Exception,
	PCONTEXT Context
);

NTDLL
ZwCallbackReturn
(
	IN PVOID Result OPTIONAL,
	IN ULONG ResultLength,
	IN NTSTATUS Status
);

NTDLL ZwResetEvent  ( IN HANDLE  EventHandle,  
					 OUT PLONG NumberOfWaitingThreads  OPTIONAL   
					 );

enum KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
};

NTDLL
KeInitializeApc
(  
	IN PKAPC Apc,
	IN PKTHREAD Thread,
	IN KAPC_ENVIRONMENT ApcIndex,
	IN PKKERNEL_ROUTINE KernelRoutine,
	IN PKRUNDOWN_ROUTINE RundownRoutine,
	IN PKNORMAL_ROUTINE NormalRoutine,
	IN ULONG ApcMode,
	IN PVOID NormalContext
);
				
NTDLL_(BOOLEAN)
KeInsertQueueApc
(
	IN PKAPC Apc,
	IN PVOID Argument1,
	IN PVOID Argument2,
	IN ULONG PriorityIncrement
);

NTDLL
PsLookupProcessByProcessId
(
	IN HANDLE ProcessId,
	OUT PEPROCESS* pProcess
);

NTDLL
PsLookupThreadByThreadId
(
	IN HANDLE ThreadId,
	OUT PETHREAD* pThread
);

NTDLL
PsLookupProcessThreadByCid
(
	IN PCLIENT_ID pCid,
	OUT PEPROCESS* pProcess OPTIONAL,
	OUT PETHREAD* pThread
);

NTDLL
ObOpenObjectByName (
					__in PCOBJECT_ATTRIBUTES ObjectAttributes,
					__in_opt POBJECT_TYPE ObjectType,
					__in KPROCESSOR_MODE AccessMode,
					__inout_opt PACCESS_STATE AccessState,
					__in_opt ACCESS_MASK DesiredAccess,
					__inout_opt PVOID ParseContext,
					__out PHANDLE Handle
					);

NTDLL
ObReferenceObjectByName (
						 __in PCUNICODE_STRING ObjectName,
						 __in ULONG Attributes,
						 __in_opt PACCESS_STATE AccessState,
						 __in_opt ACCESS_MASK DesiredAccess,
						 __in POBJECT_TYPE ObjectType,
						 __in KPROCESSOR_MODE AccessMode,
						 __inout_opt PVOID ParseContext,
						 __out PVOID *Object
						 );

NTDLL
ZwDelayExecution
(
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER Interval
);

NTDLL
ZwYieldExecution
(
);

NTDLL
NtAccessCheck(
			  _In_ PSECURITY_DESCRIPTOR SecurityDescriptor,
			  _In_ HANDLE ClientToken,
			  _In_ ACCESS_MASK DesiredAccess,
			  _In_ PGENERIC_MAPPING GenericMapping,
			  _Out_writes_bytes_(*PrivilegeSetLength) PPRIVILEGE_SET PrivilegeSet,
			  _Inout_ PULONG PrivilegeSetLength,
			  _Out_ PACCESS_MASK GrantedAccess,
			  _Out_ PNTSTATUS AccessStatus
			  );

//NTDLL
//ZwQueryVirtualMemory
//(
//	IN HANDLE ProcessHandle,
//	IN PVOID BaseAddres,
//	IN ULONG MemoryInformationClass,
//	OUT PVOID MemoryInformation,
//	IN SIZE_T MemoryInformationLength,
//	OUT PSIZE_T ReturnLength OPTIONAL
//);

NTDLL
ZwProtectVirtualMemory
(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddres,
	IN OUT PSIZE_T ProtectSize,
	IN ULONG NewProtect,
	OUT PULONG OldProtect 	
);

NTDLL
ZwReadVirtualMemory
(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddres,
	OUT PVOID Buffer,
	IN SIZE_T BufferLength,
	OUT PSIZE_T ReturnLength OPTIONAL	
);

NTDLL
ZwWriteVirtualMemory
(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddres,
	IN PVOID Buffer,
	IN SIZE_T BufferLength,
	OUT PSIZE_T ReturnLength OPTIONAL	
);

NTDLL
MmMapViewOfSection(
				   IN PVOID SectionToMap,
				   IN PEPROCESS Process,
				   IN OUT PVOID *CapturedBase,
				   IN ULONG_PTR ZeroBits,
				   IN SIZE_T CommitSize,
				   IN OUT PLARGE_INTEGER SectionOffset,
				   IN OUT PSIZE_T CapturedViewSize,
				   IN SECTION_INHERIT InheritDisposition,
				   IN ULONG AllocationType,
				   IN ULONG Protect
				   );

NTDLL
MmUnmapViewOfSection(
					 IN PEPROCESS Process,
					 IN PVOID BaseAddress
					 );

NTDLL
ZwTestAlert
(
);

NTDLL 
ZwAlertThread
(
	IN HANDLE hThread
);

NTDLL
IoCreateDriver
(
	IN const UNICODE_STRING* DriverName OPTIONAL,
	IN PDRIVER_INITIALIZE DriverInit
);

extern "C" __declspec(dllimport)
void
__fastcall
KiReleaseSpinLock( PKSPIN_LOCK);

extern "C" __declspec(dllimport)
void
__fastcall
KiAcquireSpinLock( PKSPIN_LOCK);

NTDLL
ZwTerminateThread
(
	IN HANDLE ThreadHandle OPTIONAL,
	IN NTSTATUS ExitStatus
);

NTDLL
ZwCreateThread
(
	OUT PHANDLE ThreadHandle,
	IN ULONG DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN HANDLE ProcessHandle,
	OUT PCLIENT_ID ClientId,
	PCONTEXT ThreadContext,
	IN PUSER_STACK UserStack,
	IN BOOLEAN CreateSuspended
	);

NTDLL ZwPowerInformation(
						 POWER_INFORMATION_LEVEL InformationLevel,
						 PVOID lpInputBuffer,
						 ULONG nInputBufferSize,
						 PVOID lpOutputBuffer,
						 ULONG nOutputBufferSize
						 );

NTDLL
RtlExpandEnvironmentStrings_U(
							  IN PVOID                Environment OPTIONAL,
							  IN PCUNICODE_STRING      SourceString,
							  OUT PUNICODE_STRING     DestinationString,
							  OUT PULONG              DestinationBufferLength OPTIONAL );

NTDLL RtlFormatCurrentUserKeyPath(OUT PUNICODE_STRING  RegistryPath );

NTDLL
RtlQueryInformationActivationContext
(
	IN DWORD dwFlags,
	IN HANDLE hActCtx,
	IN PVOID pvSubInstance,
	IN ULONG ulInfoClass,
	OUT PVOID pvBuffer,
	IN SIZE_T cbBuffer OPTIONAL,
	OUT SIZE_T *pcbWrittenOrRequired OPTIONAL	 
	);

NTDLL_(BOOLEAN)
RtlCreateUnicodeStringFromAsciiz
(
	OUT PUNICODE_STRING DestinationString,
	IN  const char* SourceString
	);

NTDLL
RtlGetLengthWithoutLastFullDosOrNtPathElement
(
	int zero,
	PCUNICODE_STRING Path,
	PULONG Length// in symbols
	);

NTDLL_(ULONG)
RtlGetFullPathName_U
(
	LPCWSTR lpFileName,
	DWORD nBufferLength,
	LPWSTR lpBuffer,
	LPWSTR *lpFilePart
	);

enum {
	RTL_FIND_CHAR_IN_UNICODE_STRING_START_AT_END = 1,
	RTL_FIND_CHAR_IN_UNICODE_STRING_COMPLEMENT_CHAR_SET = 2,
	RTL_FIND_CHAR_IN_UNICODE_STRING_CASE_INSENSITIVE = 4
};

NTDLL RtlFindCharInUnicodeString(
								 ULONG Flags,
								 PCUNICODE_STRING StringToSearch,
								 PCUNICODE_STRING CharSet,
								 USHORT *NonInclusivePrefixLength
								 );

enum PATH_TYPE
{
	netPath = 1,
	absolutePath,
	drivePath,
	dirPath,
	relativePath,
	ntPath,
	maxPath
};

enum RTL_PATH_TYPE {
	RtlPathTypeUnknown,
	RtlPathTypeUncAbsolute,
	RtlPathTypeDriveAbsolute,
	RtlPathTypeDriveRelative,
	RtlPathTypeRooted,
	RtlPathTypeRelative,
	RtlPathTypeLocalDevice,
	RtlPathTypeRootLocalDevice
};

NTDLL_(PATH_TYPE) RtlDetermineDosPathNameType_U(LPCWSTR DosPath);

NTDLL 
RtlDosApplyFileIsolationRedirection_Ustr(IN ULONG Flags,
										 IN PUNICODE_STRING OriginalName,
										 IN PUNICODE_STRING Extension,
										 IN OUT PUNICODE_STRING StaticString,
										 IN OUT PUNICODE_STRING DynamicString,
										 IN OUT PUNICODE_STRING *NewName,
										 IN PULONG NewFlags,
										 IN PSIZE_T FilePathLength,
										 IN PSIZE_T MaxPathSize);

EXTERN_C NTSYSAPI BOOLEAN NTAPI RtlDoesFileExists_U( _In_ PCWSTR FileName );

NTDLL_(ULONG) RtlGetNtGlobalFlags();

typedef void (CALLBACK * DO_CHECK)(LPVOID Context, LPCSTR ImportDllName);
NTDLL LdrVerifyImageMatchesChecksum(HANDLE hFile, DO_CHECK pfn, LPVOID Context, PWORD pCharacteristics);

NTDLL LdrGetDllHandle(LPCWSTR szPath, int, PCUNICODE_STRING DllName, HMODULE* phmod);

#define LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT 0x00000001
#define LDR_GET_DLL_HANDLE_EX_PIN 0x00000002

NTDLL
LdrGetDllHandleEx(
				  _In_ ULONG Flags,
				  _In_opt_ PWSTR DllPath,
				  _In_opt_ PULONG DllCharacteristics,
				  _In_ PUNICODE_STRING DllName,
				  _Out_opt_ HMODULE *DllHandle
				  );


#define FLG_SHOW_LDR_SNAPS 0x00000002

typedef NTSTATUS (CALLBACK * EnumHeapProc)(HANDLE hHeap, PVOID UserData);

NTDLL RtlEnumProcessHeaps(EnumHeapProc pfn, PVOID UserData);

#define ADD_REF_DLL_FLAG_PIN 1

NTDLL LdrAddRefDll(ULONG flags, HMODULE hmod);

NTDLL LdrInitShimEngineDynamic(HMODULE hmod);

NTDLL_(void) LdrDisableThreadCalloutsForDll(HMODULE hmod);

NTDLL LdrQueryImageFileExecutionOptions
(
 PCUNICODE_STRING ImageFileName, 
 LPCTSTR lpValueName,
 ULONG Type,
 LPVOID lpData,
 ULONG  Length,
 PULONG  ResultLength
 );

NTDLL LdrOpenImageFileOptionsKey
(
 PCUNICODE_STRING ImageFileName,
 BOOL bWowKey,
 PHANDLE phKey
 );

NTDLL LdrQueryImageFileKeyOption
(
 HANDLE hKey, 
 LPCTSTR lpValueName,
 ULONG Type,
 LPVOID lpData,
 ULONG  Length,
 PULONG  ResultLength
 );

NTDLL 
LdrShutdownThread
(
	);

NTDLL_(PIMAGE_BASE_RELOCATION)
LdrProcessRelocationBlock
(
	PVOID VirtualAddress,
	ULONG RelocCount,
	PUSHORT TypeOffset,
	LONG_PTR Delta
	);

typedef void (CALLBACK * PFNENUMERATEMODULES)
(
	_LDR_DATA_TABLE_ENTRY* mod,
	PVOID UserData,
	PBOOLEAN bStop
	);

NTDLL
LdrEnumerateLoadedModules
(
	int,
	PFNENUMERATEMODULES pfn,
	PVOID UserData
	);

NTDLL
LdrFindEntryForAddress
(
	LPCVOID Address,
	_LDR_DATA_TABLE_ENTRY** mod
	);

#define LDR_DONT_RESOLVE_DLL_REFERENCES 2

NTDLL
LdrShutdownProcess
(
);

NTDLL
LdrLoadDll
(
	PCWSTR	SearchPaths,// sz[;sz]
	PULONG	pFlags,
	PCUNICODE_STRING DllName,
	HMODULE* pDllBase
);

NTDLL LdrUnloadDll(HMODULE DllBase);

NTDLL
LdrQueryProcessModuleInformation 
(
	PRTL_PROCESS_MODULES	psmi,
	ULONG	BufferSize,
	PULONG	RealSize
);

NTDLL
LdrGetProcedureAddress
(
	HMODULE hModule,
	const ANSI_STRING * ProcedureName,
	ULONG Ordinal,
	void** pAddress
	);

NTDLL RtlRaiseStatus(NTSTATUS status);

//
// LdrAddRef Flags
//
#define LDR_ADDREF_DLL_PIN                          0x00000001

//
// LdrLockLoaderLock Flags
//
#define LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS   0x00000001
#define LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY          0x00000002

//
// LdrUnlockLoaderLock Flags
//
#define LDR_UNLOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS 0x00000001

//
// LdrGetDllHandleEx Flags
//
#define LDR_GET_DLL_HANDLE_EX_UNCHANGED_REFCOUNT    0x00000001
#define LDR_GET_DLL_HANDLE_EX_PIN                   0x00000002

#define LDR_LOCK_LOADER_LOCK_DISPOSITION_INVALID           0
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED     1
#define LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_NOT_ACQUIRED 2

NTDLL LdrLockLoaderLock(IN ULONG Flags, OUT PULONG Disposition, PULONG_PTR Cookie);

NTDLL LdrUnlockLoaderLock(IN ULONG Flags, IN ULONG_PTR Cookie);

NTDLL 
LdrFindResource_U
(
 LPVOID ImageBase, 
 const LPCWSTR pri[], 
 DWORD level, 
 PIMAGE_RESOURCE_DATA_ENTRY* ppirde
 );

NTDLL LdrAccessResource (_In_ PVOID BaseAddress, 
						 _In_ PIMAGE_RESOURCE_DATA_ENTRY ResourceDataEntry, 
						 _Out_opt_ PVOID *Resource, 
						 _Out_opt_ PULONG Size);

NTDLL_(BOOLEAN) LdrVerifyMappedImageMatchesChecksum (_In_ PVOID BaseAddress, 
													 _In_ SIZE_T NumberOfBytes, 
													 _In_ ULONG FileLength);

NTDLL
RtlFindActivationContextSectionString
(
	DWORD dwFlags,
	const GUID *lpExtensionGuid,
	ULONG ulSectionId,
	PCUNICODE_STRING StringToFind,
	PACTCTX_SECTION_KEYED_DATA ReturnedData
	);

NTDLL RtlValidAcl(PACL Acl);

NTDLL RtlConvertSidToUnicodeString(
								   PUNICODE_STRING UnicodeString,
								   PSID Sid,
								   BOOLEAN AllocateDestinationString
								   );

NTDLL
ZwAdjustPrivilegesToken (
						 __in      HANDLE TokenHandle,
						 __in      BOOL DisableAllPrivileges,
						 __in_opt  PTOKEN_PRIVILEGES NewState,
						 __in      DWORD BufferLength,
						 __out_bcount_part_opt(BufferLength, *ReturnLength) PTOKEN_PRIVILEGES PreviousState,
						 __out_opt PDWORD ReturnLength
						 );

NTDLL
ZwQuerySection
(
	IN HANDLE SectionHandle,
	IN ULONG SectionInformationClass,
	OUT PVOID SectionInformation,
	IN ULONG SectionInformationLength,
	OUT PSIZE_T ResultLength OPTIONAL
);

#define RTL_USER_PROC_PARAMS_NORMALIZED 0x00000001
#define RTL_USER_PROC_PROFILE_USER 0x00000002
#define RTL_USER_PROC_PROFILE_KERNEL 0x00000004
#define RTL_USER_PROC_PROFILE_SERVER 0x00000008
#define RTL_USER_PROC_RESERVE_1MB 0x00000020
#define RTL_USER_PROC_RESERVE_16MB 0x00000040
#define RTL_USER_PROC_CASE_SENSITIVE 0x00000080
#define RTL_USER_PROC_DISABLE_HEAP_DECOMMIT 0x00000100
#define RTL_USER_PROC_DLL_REDIRECTION_LOCAL 0x00001000
#define RTL_USER_PROC_APP_MANIFEST_PRESENT 0x00002000
#define RTL_USER_PROC_IMAGE_KEY_MISSING 0x00004000
#define RTL_USER_PROC_OPTIN_PROCESS 0x00020000

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParameters(
						   _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
						   _In_ PCUNICODE_STRING ImagePathName,
						   _In_opt_ PCUNICODE_STRING DllPath,
						   _In_opt_ PCUNICODE_STRING CurrentDirectory,
						   _In_opt_ PCUNICODE_STRING CommandLine,
						   _In_opt_ PVOID Environment,
						   _In_opt_ PCUNICODE_STRING WindowTitle,
						   _In_opt_ PCUNICODE_STRING DesktopInfo,
						   _In_opt_ PCUNICODE_STRING ShellInfo,
						   _In_opt_ PCUNICODE_STRING RuntimeData
						   );

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateProcessParametersEx(
							 _Out_ PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
							 _In_ PCUNICODE_STRING ImagePathName,
							 _In_opt_ PCUNICODE_STRING DllPath,
							 _In_opt_ PCUNICODE_STRING CurrentDirectory,
							 _In_opt_ PCUNICODE_STRING CommandLine,
							 _In_opt_ PVOID Environment,
							 _In_opt_ PCUNICODE_STRING WindowTitle,
							 _In_opt_ PCUNICODE_STRING DesktopInfo,
							 _In_opt_ PCUNICODE_STRING ShellInfo,
							 _In_opt_ PCUNICODE_STRING RuntimeData,
							 _In_ ULONG Flags // pass RTL_USER_PROC_PARAMS_NORMALIZED to keep parameters normalized
							 );

EXTERN_C
NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyProcessParameters(
							_In_ _Post_invalid_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
							);

EXTERN_C
NTSYSAPI
PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlNormalizeProcessParams(
						  _Inout_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
						  );

EXTERN_C
NTSYSAPI
PRTL_USER_PROCESS_PARAMETERS
NTAPI
RtlDeNormalizeProcessParams(
							_Inout_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters
							);

NTDLL
RtlQueryProcessDebugInformation(
								IN HANDLE UniqueProcessId,
								IN ULONG Flags,
								IN OUT PRTL_DEBUG_INFORMATION Buffer
								);

NTDLL_(PRTL_DEBUG_INFORMATION)
RtlCreateQueryDebugBuffer(
						  IN ULONG MaximumCommit OPTIONAL,
						  IN BOOLEAN UseEventPair
						  );

NTDLL
RtlDestroyQueryDebugBuffer(
						   IN PRTL_DEBUG_INFORMATION Buffer
						   );

NTDLL
RtlCreateUserThread
(
	IN HANDLE hProcess,
	PVOID   SecurityDescriptor,
	BOOLEAN CreateSuspended,
	ULONG	ZeroBits,
	SIZE_T	StackReserve,
	SIZE_T	StackCommit,
	PVOID	EntryPoint,
	const void*	Argument,
	PHANDLE	phThread,
	PCLIENT_ID pCid
);

NTDLL_(BOOLEAN)
RtlDosPathNameToNtPathName_U
(
	PCWSTR DosPathName,
	PUNICODE_STRING NtPathName,
	PWSTR* FilePart,
	PUNICODE_STRING
	);

NTDLL RtlDosPathNameToNtPathName_U_WithStatus (IN PCWSTR  	DosName,
											   OUT PUNICODE_STRING  	NtName,
											   OUT PWSTR *  	PartName,
											   OUT PVOID  	RelativeName 
											   );
NTDLL_(TEB_ACTIVE_FRAME*) RtlGetFrame();

NTDLL_(VOID) RtlPushFrame(TEB_ACTIVE_FRAME* Frame);
NTDLL_(VOID) RtlPopFrame(TEB_ACTIVE_FRAME* Frame);

NTDLL
ZwQueryObject
(
	IN HANDLE ObjHandle,
	IN OBJECT_INFORMATION_CLASS InfoCls,
	OUT PVOID ObjectInfo,
	IN ULONG ObjectInfoLen,
	OUT PULONG RetLen OPTIONAL
);

NTDLL
ZwSetInformationObject
(
	IN HANDLE ObjHandle,
	IN OBJECT_INFORMATION_CLASS InfoCls,
	OUT PVOID ObjectInfo,
	IN ULONG ObjectInfoLen
);

NTDLL
ZwQueryDirectoryObject
(
	IN HANDLE DirectoryHandle,
	OUT PVOID Buffer,
	IN ULONG BufferLength,
	IN BOOLEAN ReturnSingleEntry,
	IN BOOLEAN RestarnScan,
	IN OUT PULONG Context,
	OUT PULONG ReturnLength OPTIONAL
);

NTDLL_(void)
RtlInitializeResource
(
	IN PVOID cs
);

NTDLL_(void)
RtlDeleteResource
(
	IN PVOID cs
);

NTDLL_(void)
RtlReleaseResource
(
	IN PVOID cs
);

NTDLL
RtlConvertSharedToExclusive
(
	IN PVOID cs
);

NTDLL
RtlConvertExclusiveToShared
(
	IN PVOID cs
);

NTDLL_(BOOLEAN)
RtlAcquireResourceExclusive
(
	IN PVOID cs,
	IN BOOLEAN Wait
);

NTDLL_(BOOLEAN)
RtlAcquireResourceShared
(
	IN PVOID cs,
	IN BOOLEAN Wait
);

NTDLL
RtlDumpResource
(
	IN PVOID cs
);

NTDLL
ZwQueryTimerResolution
(
	PULONG	MaxPeriod,
	PULONG	MinPeriod,
	PULONG	CurrentPeriod
	);

NTDLL
ZwSetTimerResolution
(
	ULONG	RequestPeriod,
	BOOLEAN Set,
	PULONG	ActualPeriod
	);

enum ATOM_INFORMATION_CLASS
{ 
	AtomBasicInformation,AtomListInformation
};

NTDLL ZwQueryInformationAtom
(
	USHORT Atom,
	ATOM_INFORMATION_CLASS AtomInformationClass,
	PVOID AtomInformation,
	ULONG AtomInformationLength,
	PULONG ReturnLength
	);

struct ATOM_LIST_INFORMATION 
{
	ULONG NumberOfAtoms;
	ATOM Atoms[];
};

struct ATOM_BASIC_INFORMATION
{
	USHORT ReferenceCount;
	USHORT Pinned;
	USHORT NameLength;
	WCHAR Name[];
};

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)

enum LDR_DLL_NOTIFICATION_REASON {
	LDR_DLL_NOTIFICATION_REASON_LOADED = 1,
	LDR_DLL_NOTIFICATION_REASON_UNLOADED
};

struct LDR_DLL_NOTIFICATION_DATA {
	ULONG Flags;                    //Reserved.
	PCUNICODE_STRING FullDllName;   //The full path name of the DLL module.
	PCUNICODE_STRING BaseDllName;   //The base file name of the DLL module.
	PVOID DllBase;                  //A pointer to the base address for the DLL in memory.
	ULONG SizeOfImage;              //The size of the DLL image, in bytes.
};

typedef const LDR_DLL_NOTIFICATION_DATA * PCLDR_DLL_NOTIFICATION_DATA;

typedef VOID (CALLBACK *PLDR_DLL_NOTIFICATION_FUNCTION)(
	_In_     LDR_DLL_NOTIFICATION_REASON NotificationReason,
	_In_     PCLDR_DLL_NOTIFICATION_DATA NotificationData,
	_In_opt_ PVOID                       Context
	);

NTDLL LdrRegisterDllNotification(
								 _In_     ULONG                          Flags,
								 _In_     PLDR_DLL_NOTIFICATION_FUNCTION NotificationFunction,
								 _In_opt_ PVOID                          Context,
								 _Out_    PVOID                          *Cookie
								 );

NTDLL LdrUnregisterDllNotification(_In_ PVOID Cookie);

NTDLL
ZwCreateKeyedEvent (
					_Out_ PHANDLE KeyedEventHandle,
					_In_ ACCESS_MASK DesiredAccess,
					_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
					_In_ ULONG Flags
					);
NTDLL
ZwOpenKeyedEvent (
				  _Out_ PHANDLE KeyedEventHandle,
				  _In_ ACCESS_MASK DesiredAccess,
				  _In_ POBJECT_ATTRIBUTES ObjectAttributes
				  );
NTDLL
ZwReleaseKeyedEvent (
					 _In_ HANDLE KeyedEventHandle,
					 _In_ PVOID KeyValue,
					 _In_ BOOLEAN Alertable,
					 _In_opt_ PLARGE_INTEGER Timeout
					 );
NTDLL
ZwWaitForKeyedEvent (
					 _In_ HANDLE KeyedEventHandle,
					 _In_ PVOID KeyValue,
					 _In_ BOOLEAN Alertable,
					 _In_opt_ PLARGE_INTEGER Timeout
					 );

NTDLL
ZwAlertThreadByThreadId (
						 _In_ HANDLE ThreadId
						 );


NTDLL
ZwWaitForAlertByThreadId(
						 _In_ PVOID ,
						 _In_opt_ PLARGE_INTEGER Timeout
						 );

NTDLL RtlWaitOnAddress(_In_     void volatile *Address,
					   _In_     PVOID CompareAddress,
					   _In_     SIZE_T AddressSize,
					   _In_opt_ PLARGE_INTEGER Timeout);

NTDLL RtlWakeAddressSingle(_In_ PVOID Address);

NTDLL RtlWakeAddressAll(_In_ PVOID Address);


#endif//_WIN32_WINNT_VISTA

NTDLL__(VOID) FASTCALL ExfAcquirePushLockShared(PEX_PUSH_LOCK PushLock);
NTDLL__(VOID) FASTCALL ExfAcquirePushLockExclusive(PEX_PUSH_LOCK PushLock);
NTDLL__(VOID) FASTCALL ExfReleasePushLock(PEX_PUSH_LOCK PushLock);
NTDLL__(VOID) FASTCALL ExfReleasePushLockShared(PEX_PUSH_LOCK PushLock);
NTDLL__(VOID) FASTCALL ExfReleasePushLockExclusive(PEX_PUSH_LOCK PushLock);


