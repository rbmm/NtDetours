#pragma once

_EXTERN_C_BEGIN
// Environment

NTSYSAPI
NTSTATUS
NTAPI
RtlCreateEnvironment(
    _In_ BOOLEAN CloneCurrentEnvironment,
    _Out_ PVOID *Environment
    );

// begin_rev
#define RTL_CREATE_ENVIRONMENT_TRANSLATE 0x1 // translate from multi-byte to Unicode
#define RTL_CREATE_ENVIRONMENT_TRANSLATE_FROM_OEM 0x2 // translate from OEM to Unicode (Translate flag must also be set)
#define RTL_CREATE_ENVIRONMENT_EMPTY 0x4 // create empty environment block
// end_rev

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
// private
NTSYSAPI
NTSTATUS
NTAPI
RtlCreateEnvironmentEx(
    _In_ PVOID SourceEnv,
    _Out_ PVOID *Environment,
    _In_ ULONG Flags
    );
#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlDestroyEnvironment(
    _In_ PVOID Environment
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSetCurrentEnvironment(
    _In_ PVOID Environment,
    _Out_opt_ PVOID *PreviousEnvironment
    );

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
// private
NTSYSAPI
NTSTATUS
NTAPI
RtlSetEnvironmentVar(
    _In_opt_ PWSTR *Environment,
    _In_reads_(NameLength) PCWSTR Name,
    _In_ SIZE_T NameLength,
    _In_reads_(ValueLength) PCWSTR Value,
    _In_ SIZE_T ValueLength
    );
#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlSetEnvironmentVariable(
    _In_opt_ PVOID *Environment,
    _In_ PCUNICODE_STRING Name,
    _In_opt_ PCUNICODE_STRING Value
    );

#if (PHNT_VERSION >= PHNT_VISTA)
// private
NTSYSAPI
NTSTATUS
NTAPI
RtlQueryEnvironmentVariable(
    _In_opt_ PVOID Environment,
    _In_reads_(NameLength) PCWSTR Name,
    _In_ SIZE_T NameLength,
    _Out_writes_(ValueLength) PWSTR Value,
    _In_ SIZE_T ValueLength,
    _Out_ PSIZE_T ReturnLength
    );
#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryEnvironmentVariable_U(
    _In_opt_ PVOID Environment,
    _In_ PCUNICODE_STRING Name,
    _Out_ PUNICODE_STRING Value
    );

#if (_WIN32_WINNT >= _WIN32_WINNT_VISTA)
// private
NTSYSAPI
NTSTATUS
NTAPI
RtlExpandEnvironmentStrings(
    _In_opt_ PVOID Environment,
    _In_reads_(SrcLength) PCWSTR Src,
    _In_ SIZE_T SrcLength,
    _Out_writes_(DstLength) PWSTR Dst,
    _In_ SIZE_T DstLength,
    _Out_opt_ PSIZE_T ReturnLength
    );
#endif

NTSYSAPI
NTSTATUS
NTAPI
RtlExpandEnvironmentStrings_U(
    _In_opt_ PVOID Environment,
    _In_ PCUNICODE_STRING Source,
    _Out_ PUNICODE_STRING Destination,
    _Out_opt_ PULONG ReturnedLength
    );

NTSYSAPI
NTSTATUS
NTAPI
RtlSetEnvironmentStrings(
    _In_ PWCHAR NewEnvironment,
    _In_ SIZE_T NewEnvironmentSize
    );

_EXTERN_C_END