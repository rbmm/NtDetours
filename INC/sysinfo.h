#pragma once
//
// Shutdown types for NtShutdownSystem
//
typedef enum _SHUTDOWN_ACTION
{
    ShutdownNoReboot,
    ShutdownReboot,
    ShutdownPowerOff
} SHUTDOWN_ACTION;

//
// Responses for NtRaiseHardError
//
typedef enum _HARDERROR_RESPONSE_OPTION
{
    OptionAbortRetryIgnore,
    OptionOk,
    OptionOkCancel,
    OptionRetryCancel,
    OptionYesNo,
    OptionYesNoCancel,
    OptionShutdownSystem
} HARDERROR_RESPONSE_OPTION, *PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE
{
    ResponseReturnToCaller,
    ResponseNotHandled,
    ResponseAbort,
    ResponseCancel,
    ResponseIgnore,
    ResponseNo,
    ResponseOk,
    ResponseRetry,
    ResponseYes,
    ResponseTryAgain,
    ResponseContinue
} HARDERROR_RESPONSE, *PHARDERROR_RESPONSE;

typedef struct _EVENT_BASIC_INFORMATION
{
	EVENT_TYPE EventType;
	LONG EventState;
} EVENT_BASIC_INFORMATION, *PEVENT_BASIC_INFORMATION;

enum EVENT_INFORMATION_CLASS
{
	EventBasicInformation
};

struct DIRECTORY_BASIC_INFORMATION
{
	UNICODE_STRING ObjectName;
	UNICODE_STRING ObjectTypeName;
};

//
//  System Information Classes for NtQuerySystemInformation
//
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	SystemLocksInformation, // q: RTL_PROCESS_LOCKS
	SystemStackTraceInformation, // q: RTL_PROCESS_BACKTRACES
	SystemPagedPoolInformation, // not implemented
	SystemNonPagedPoolInformation, // not implemented
	SystemHandleInformation, // q: SYSTEM_HANDLE_INFORMATION
	SystemObjectInformation, // q: SYSTEM_OBJECTTYPE_INFORMATION mixed with SYSTEM_OBJECT_INFORMATION
	SystemPageFileInformation, // q: SYSTEM_PAGEFILE_INFORMATION
	SystemVdmInstemulInformation, // q: SYSTEM_VDM_INSTEMUL_INFO
	SystemVdmBopInformation, // not implemented // 20
	SystemFileCacheInformation, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemCache)
	SystemPoolTagInformation, // q: SYSTEM_POOLTAG_INFORMATION
	SystemInterruptInformation, // q: SYSTEM_INTERRUPT_INFORMATION
	SystemDpcBehaviorInformation, // q: SYSTEM_DPC_BEHAVIOR_INFORMATION; s: SYSTEM_DPC_BEHAVIOR_INFORMATION (requires SeLoadDriverPrivilege)
	SystemFullMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
	SystemLoadGdiDriverInformation, // s (kernel-mode only)
	SystemUnloadGdiDriverInformation, // s (kernel-mode only)
	SystemTimeAdjustmentInformation, // q: SYSTEM_QUERY_TIME_ADJUST_INFORMATION; s: SYSTEM_SET_TIME_ADJUST_INFORMATION (requires SeSystemtimePrivilege)
	SystemSummaryMemoryInformation, // not implemented // SYSTEM_MEMORY_USAGE_INFORMATION
	SystemMirrorMemoryInformation, // s (requires license value "Kernel-MemoryMirroringSupported") (requires SeShutdownPrivilege) // 30
	SystemPerformanceTraceInformation, // q; s: (type depends on EVENT_TRACE_INFORMATION_CLASS)
	SystemObsolete0, // not implemented
	SystemExceptionInformation, // q: SYSTEM_EXCEPTION_INFORMATION
	SystemCrashDumpStateInformation, // s: SYSTEM_CRASH_DUMP_STATE_INFORMATION (requires SeDebugPrivilege)
	SystemKernelDebuggerInformation, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION
	SystemContextSwitchInformation, // q: SYSTEM_CONTEXT_SWITCH_INFORMATION
	SystemRegistryQuotaInformation, // q: SYSTEM_REGISTRY_QUOTA_INFORMATION; s (requires SeIncreaseQuotaPrivilege)
	SystemExtendServiceTableInformation, // s (requires SeLoadDriverPrivilege) // loads win32k only
	SystemPrioritySeperation, // s (requires SeTcbPrivilege)
	SystemVerifierAddDriverInformation, // s (requires SeDebugPrivilege) // 40
	SystemVerifierRemoveDriverInformation, // s (requires SeDebugPrivilege)
	SystemProcessorIdleInformation, // q: SYSTEM_PROCESSOR_IDLE_INFORMATION
	SystemLegacyDriverInformation, // q: SYSTEM_LEGACY_DRIVER_INFORMATION
	SystemCurrentTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION
	SystemLookasideInformation, // q: SYSTEM_LOOKASIDE_INFORMATION
	SystemTimeSlipNotification, // s: HANDLE (NtCreateEvent) (requires SeSystemtimePrivilege)
	SystemSessionCreate, // not implemented
	SystemSessionDetach, // not implemented
	SystemSessionInformation, // not implemented (SYSTEM_SESSION_INFORMATION)
	SystemRangeStartInformation, // q: SYSTEM_RANGE_START_INFORMATION // 50
	SystemVerifierInformation, // q: SYSTEM_VERIFIER_INFORMATION; s (requires SeDebugPrivilege)
	SystemVerifierThunkExtend, // s (kernel-mode only)
	SystemSessionProcessInformation, // q: SYSTEM_SESSION_PROCESS_INFORMATION
	SystemLoadGdiDriverInSystemSpace, // s: SYSTEM_GDI_DRIVER_INFORMATION (kernel-mode only) (same as SystemLoadGdiDriverInformation)
	SystemNumaProcessorMap, // q: SYSTEM_NUMA_INFORMATION
	SystemPrefetcherInformation, // q; s: PREFETCHER_INFORMATION // PfSnQueryPrefetcherInformation
	SystemExtendedProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemRecommendedSharedDataAlignment, // q: ULONG // KeGetRecommendedSharedDataAlignment
	SystemComPlusPackage, // q; s: ULONG
	SystemNumaAvailableMemory, // q: SYSTEM_NUMA_INFORMATION // 60
	SystemProcessorPowerInformation, // q: SYSTEM_PROCESSOR_POWER_INFORMATION
	SystemEmulationBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemEmulationProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemExtendedHandleInformation, // q: SYSTEM_HANDLE_INFORMATION_EX
	SystemLostDelayedWriteInformation, // q: ULONG
	SystemBigPoolInformation, // q: SYSTEM_BIGPOOL_INFORMATION
	SystemSessionPoolTagInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION
	SystemSessionMappedViewInformation, // q: SYSTEM_SESSION_MAPPED_VIEW_INFORMATION
	SystemHotpatchInformation, // q; s: SYSTEM_HOTPATCH_CODE_INFORMATION
	SystemObjectSecurityMode, // q: ULONG // 70
	SystemWatchdogTimerHandler, // s: SYSTEM_WATCHDOG_HANDLER_INFORMATION // (kernel-mode only)
	SystemWatchdogTimerInformation, // q: SYSTEM_WATCHDOG_TIMER_INFORMATION // (kernel-mode only)
	SystemLogicalProcessorInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION
	SystemWow64SharedInformationObsolete, // not implemented
	SystemRegisterFirmwareTableInformationHandler, // s: SYSTEM_FIRMWARE_TABLE_HANDLER // (kernel-mode only)
	SystemFirmwareTableInformation, // SYSTEM_FIRMWARE_TABLE_INFORMATION
	SystemModuleInformationEx, // q: RTL_PROCESS_MODULE_INFORMATION_EX
	SystemVerifierTriageInformation, // not implemented
	SystemSuperfetchInformation, // q; s: SUPERFETCH_INFORMATION // PfQuerySuperfetchInformation
	SystemMemoryListInformation, // q: SYSTEM_MEMORY_LIST_INFORMATION; s: SYSTEM_MEMORY_LIST_COMMAND (requires SeProfileSingleProcessPrivilege) // 80
	SystemFileCacheInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (same as SystemFileCacheInformation)
	SystemThreadPriorityClientIdInformation, // s: SYSTEM_THREAD_CID_PRIORITY_INFORMATION (requires SeIncreaseBasePriorityPrivilege)
	SystemProcessorIdleCycleTimeInformation, // q: SYSTEM_PROCESSOR_IDLE_CYCLE_TIME_INFORMATION[]
	SystemVerifierCancellationInformation, // SYSTEM_VERIFIER_CANCELLATION_INFORMATION // name:wow64:whNT32QuerySystemVerifierCancellationInformation
	SystemProcessorPowerInformationEx, // not implemented
	SystemRefTraceInformation, // q; s: SYSTEM_REF_TRACE_INFORMATION // ObQueryRefTraceInformation
	SystemSpecialPoolInformation, // q; s: SYSTEM_SPECIAL_POOL_INFORMATION (requires SeDebugPrivilege) // MmSpecialPoolTag, then MmSpecialPoolCatchOverruns != 0
	SystemProcessIdInformation, // q: SYSTEM_PROCESS_ID_INFORMATION
	SystemErrorPortInformation, // s (requires SeTcbPrivilege)
	SystemBootEnvironmentInformation, // q: SYSTEM_BOOT_ENVIRONMENT_INFORMATION // 90
	SystemHypervisorInformation, // q: SYSTEM_HYPERVISOR_QUERY_INFORMATION
	SystemVerifierInformationEx, // q; s: SYSTEM_VERIFIER_INFORMATION_EX
	SystemTimeZoneInformation, // q; s: RTL_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
	SystemImageFileExecutionOptionsInformation, // s: SYSTEM_IMAGE_FILE_EXECUTION_OPTIONS_INFORMATION (requires SeTcbPrivilege)
	SystemCoverageInformation, // q: COVERAGE_MODULES s: COVERAGE_MODULE_REQUEST // ExpCovQueryInformation (requires SeDebugPrivilege)
	SystemPrefetchPatchInformation, // SYSTEM_PREFETCH_PATCH_INFORMATION
	SystemVerifierFaultsInformation, // s: SYSTEM_VERIFIER_FAULTS_INFORMATION (requires SeDebugPrivilege)
	SystemSystemPartitionInformation, // q: SYSTEM_SYSTEM_PARTITION_INFORMATION
	SystemSystemDiskInformation, // q: SYSTEM_SYSTEM_DISK_INFORMATION
	SystemProcessorPerformanceDistribution, // q: SYSTEM_PROCESSOR_PERFORMANCE_DISTRIBUTION // 100
	SystemNumaProximityNodeInformation, // q; s: SYSTEM_NUMA_PROXIMITY_MAP
	SystemDynamicTimeZoneInformation, // q; s: RTL_DYNAMIC_TIME_ZONE_INFORMATION (requires SeTimeZonePrivilege)
	SystemCodeIntegrityInformation, // q: SYSTEM_CODEINTEGRITY_INFORMATION // SeCodeIntegrityQueryInformation
	SystemProcessorMicrocodeUpdateInformation, // s: SYSTEM_PROCESSOR_MICROCODE_UPDATE_INFORMATION
	SystemProcessorBrandString, // q: CHAR[] // HaliQuerySystemInformation -> HalpGetProcessorBrandString, info class 23
	SystemVirtualAddressInformation, // q: SYSTEM_VA_LIST_INFORMATION[]; s: SYSTEM_VA_LIST_INFORMATION[] (requires SeIncreaseQuotaPrivilege) // MmQuerySystemVaInformation
	SystemLogicalProcessorAndGroupInformation, // q: SYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX // since WIN7 // KeQueryLogicalProcessorRelationship
	SystemProcessorCycleTimeInformation, // q: SYSTEM_PROCESSOR_CYCLE_TIME_INFORMATION[]
	SystemStoreInformation, // q; s: SYSTEM_STORE_INFORMATION (requires SeProfileSingleProcessPrivilege) // SmQueryStoreInformation
	SystemRegistryAppendString, // s: SYSTEM_REGISTRY_APPEND_STRING_PARAMETERS // 110
	SystemAitSamplingValue, // s: ULONG (requires SeProfileSingleProcessPrivilege)
	SystemVhdBootInformation, // q: SYSTEM_VHD_BOOT_INFORMATION
	SystemCpuQuotaInformation, // q; s: PS_CPU_QUOTA_QUERY_INFORMATION
	SystemNativeBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemErrorPortTimeouts, // SYSTEM_ERROR_PORT_TIMEOUTS
	SystemLowPriorityIoInformation, // q: SYSTEM_LOW_PRIORITY_IO_INFORMATION
	SystemTpmBootEntropyInformation, // q: TPM_BOOT_ENTROPY_NT_RESULT // ExQueryTpmBootEntropyInformation
	SystemVerifierCountersInformation, // q: SYSTEM_VERIFIER_COUNTERS_INFORMATION
	SystemPagedPoolInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypePagedPool)
	SystemSystemPtesInformationEx, // q: SYSTEM_FILECACHE_INFORMATION; s (requires SeIncreaseQuotaPrivilege) (info for WorkingSetTypeSystemPtes) // 120
	SystemNodeDistanceInformation,
	SystemAcpiAuditInformation, // q: SYSTEM_ACPI_AUDIT_INFORMATION // HaliQuerySystemInformation -> HalpAuditQueryResults, info class 26
	SystemBasicPerformanceInformation, // q: SYSTEM_BASIC_PERFORMANCE_INFORMATION // name:wow64:whNtQuerySystemInformation_SystemBasicPerformanceInformation
	SystemQueryPerformanceCounterInformation, // q: SYSTEM_QUERY_PERFORMANCE_COUNTER_INFORMATION // since WIN7 SP1
	SystemSessionBigPoolInformation, // q: SYSTEM_SESSION_POOLTAG_INFORMATION // since WIN8
	SystemBootGraphicsInformation, // q; s: SYSTEM_BOOT_GRAPHICS_INFORMATION (kernel-mode only)
	SystemScrubPhysicalMemoryInformation, // q; s: MEMORY_SCRUB_INFORMATION
	SystemBadPageInformation,
	SystemProcessorProfileControlArea, // q; s: SYSTEM_PROCESSOR_PROFILE_CONTROL_AREA
	SystemCombinePhysicalMemoryInformation, // s: MEMORY_COMBINE_INFORMATION, MEMORY_COMBINE_INFORMATION_EX, MEMORY_COMBINE_INFORMATION_EX2 // 130
	SystemEntropyInterruptTimingInformation, // q; s: SYSTEM_ENTROPY_TIMING_INFORMATION
	SystemConsoleInformation, // q: SYSTEM_CONSOLE_INFORMATION
	SystemPlatformBinaryInformation, // q: SYSTEM_PLATFORM_BINARY_INFORMATION (requires SeTcbPrivilege)
	SystemPolicyInformation, // q: SYSTEM_POLICY_INFORMATION
	SystemHypervisorProcessorCountInformation, // q: SYSTEM_HYPERVISOR_PROCESSOR_COUNT_INFORMATION
	SystemDeviceDataInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemDeviceDataEnumerationInformation, // q: SYSTEM_DEVICE_DATA_INFORMATION
	SystemMemoryTopologyInformation, // q: SYSTEM_MEMORY_TOPOLOGY_INFORMATION
	SystemMemoryChannelInformation, // q: SYSTEM_MEMORY_CHANNEL_INFORMATION
	SystemBootLogoInformation, // q: SYSTEM_BOOT_LOGO_INFORMATION // 140
	SystemProcessorPerformanceInformationEx, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION_EX // since WINBLUE
	SystemCriticalProcessErrorLogInformation,
	SystemSecureBootPolicyInformation, // q: SYSTEM_SECUREBOOT_POLICY_INFORMATION
	SystemPageFileInformationEx, // q: SYSTEM_PAGEFILE_INFORMATION_EX
	SystemSecureBootInformation, // q: SYSTEM_SECUREBOOT_INFORMATION
	SystemEntropyInterruptTimingRawInformation,
	SystemPortableWorkspaceEfiLauncherInformation, // q: SYSTEM_PORTABLE_WORKSPACE_EFI_LAUNCHER_INFORMATION
	SystemFullProcessInformation, // q: SYSTEM_PROCESS_INFORMATION with SYSTEM_PROCESS_INFORMATION_EXTENSION (requires admin)
	SystemKernelDebuggerInformationEx, // q: SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX
	SystemBootMetadataInformation, // 150
	SystemSoftRebootInformation, // q: ULONG
	SystemElamCertificateInformation, // s: SYSTEM_ELAM_CERTIFICATE_INFORMATION
	SystemOfflineDumpConfigInformation, // q: OFFLINE_CRASHDUMP_CONFIGURATION_TABLE_V2
	SystemProcessorFeaturesInformation, // q: SYSTEM_PROCESSOR_FEATURES_INFORMATION
	SystemRegistryReconciliationInformation, // s: NULL (requires admin) (flushes registry hives)
	SystemEdidInformation, // q: SYSTEM_EDID_INFORMATION
	SystemManufacturingInformation, // q: SYSTEM_MANUFACTURING_INFORMATION // since THRESHOLD
	SystemEnergyEstimationConfigInformation, // q: SYSTEM_ENERGY_ESTIMATION_CONFIG_INFORMATION
	SystemHypervisorDetailInformation, // q: SYSTEM_HYPERVISOR_DETAIL_INFORMATION
	SystemProcessorCycleStatsInformation, // q: SYSTEM_PROCESSOR_CYCLE_STATS_INFORMATION // 160
	SystemVmGenerationCountInformation,
	SystemTrustedPlatformModuleInformation, // q: SYSTEM_TPM_INFORMATION
	SystemKernelDebuggerFlags, // SYSTEM_KERNEL_DEBUGGER_FLAGS
	SystemCodeIntegrityPolicyInformation, // q: SYSTEM_CODEINTEGRITYPOLICY_INFORMATION
	SystemIsolatedUserModeInformation, // q: SYSTEM_ISOLATED_USER_MODE_INFORMATION
	SystemHardwareSecurityTestInterfaceResultsInformation,
	SystemSingleModuleInformation, // q: SYSTEM_SINGLE_MODULE_INFORMATION
	SystemAllowedCpuSetsInformation,
	SystemVsmProtectionInformation, // q: SYSTEM_VSM_PROTECTION_INFORMATION (previously SystemDmaProtectionInformation)
	SystemInterruptCpuSetsInformation, // q: SYSTEM_INTERRUPT_CPU_SET_INFORMATION // 170
	SystemSecureBootPolicyFullInformation, // q: SYSTEM_SECUREBOOT_POLICY_FULL_INFORMATION
	SystemCodeIntegrityPolicyFullInformation,
	SystemAffinitizedInterruptProcessorInformation, // (requires SeIncreaseBasePriorityPrivilege)
	SystemRootSiloInformation, // q: SYSTEM_ROOT_SILO_INFORMATION
	SystemCpuSetInformation, // q: SYSTEM_CPU_SET_INFORMATION // since THRESHOLD2
	SystemCpuSetTagInformation, // q: SYSTEM_CPU_SET_TAG_INFORMATION
	SystemWin32WerStartCallout,
	SystemSecureKernelProfileInformation, // q: SYSTEM_SECURE_KERNEL_HYPERGUARD_PROFILE_INFORMATION
	SystemCodeIntegrityPlatformManifestInformation, // q: SYSTEM_SECUREBOOT_PLATFORM_MANIFEST_INFORMATION // since REDSTONE
	SystemInterruptSteeringInformation, // SYSTEM_INTERRUPT_STEERING_INFORMATION_INPUT // 180
	SystemSupportedProcessorArchitectures, // in: HANDLE, out: SYSTEM_SUPPORTED_PROCESSOR_ARCHITECTURES_INFORMATION[] (Max 5 structs) // NtQuerySystemInformationEx
	SystemMemoryUsageInformation, // q: SYSTEM_MEMORY_USAGE_INFORMATION
	SystemCodeIntegrityCertificateInformation, // q: SYSTEM_CODEINTEGRITY_CERTIFICATE_INFORMATION
	SystemPhysicalMemoryInformation, // q: SYSTEM_PHYSICAL_MEMORY_INFORMATION // since REDSTONE2
	SystemControlFlowTransition,
	SystemKernelDebuggingAllowed, // s: ULONG
	SystemActivityModerationExeState, // SYSTEM_ACTIVITY_MODERATION_EXE_STATE
	SystemActivityModerationUserSettings, // SYSTEM_ACTIVITY_MODERATION_USER_SETTINGS
	SystemCodeIntegrityPoliciesFullInformation,
	SystemCodeIntegrityUnlockInformation, // SYSTEM_CODEINTEGRITY_UNLOCK_INFORMATION // 190
	SystemIntegrityQuotaInformation,
	SystemFlushInformation, // q: SYSTEM_FLUSH_INFORMATION
	SystemProcessorIdleMaskInformation, // q: ULONG_PTR // since REDSTONE3
	SystemSecureDumpEncryptionInformation,
	SystemWriteConstraintInformation, // SYSTEM_WRITE_CONSTRAINT_INFORMATION
	SystemKernelVaShadowInformation, // SYSTEM_KERNEL_VA_SHADOW_INFORMATION
	SystemHypervisorSharedPageInformation, // SYSTEM_HYPERVISOR_SHARED_PAGE_INFORMATION // since REDSTONE4
	SystemFirmwareBootPerformanceInformation,
	SystemCodeIntegrityVerificationInformation, // SYSTEM_CODEINTEGRITYVERIFICATION_INFORMATION
	SystemFirmwarePartitionInformation, // SYSTEM_FIRMWARE_PARTITION_INFORMATION // 200
	SystemSpeculationControlInformation, // SYSTEM_SPECULATION_CONTROL_INFORMATION // (CVE-2017-5715) REDSTONE3 and above.
	SystemDmaGuardPolicyInformation, // SYSTEM_DMA_GUARD_POLICY_INFORMATION
	SystemEnclaveLaunchControlInformation, // SYSTEM_ENCLAVE_LAUNCH_CONTROL_INFORMATION
	SystemWorkloadAllowedCpuSetsInformation, // SYSTEM_WORKLOAD_ALLOWED_CPU_SET_INFORMATION // since REDSTONE5
	SystemCodeIntegrityUnlockModeInformation,
	SystemLeapSecondInformation, // SYSTEM_LEAP_SECOND_INFORMATION
	SystemFlags2Information, // q: SYSTEM_FLAGS_INFORMATION
	SystemSecurityModelInformation, // SYSTEM_SECURITY_MODEL_INFORMATION // since 19H1
	SystemCodeIntegritySyntheticCacheInformation,
	SystemFeatureConfigurationInformation, // SYSTEM_FEATURE_CONFIGURATION_INFORMATION // since 20H1 // 210
	SystemFeatureConfigurationSectionInformation, // SYSTEM_FEATURE_CONFIGURATION_SECTIONS_INFORMATION
	SystemFeatureUsageSubscriptionInformation, // SYSTEM_FEATURE_USAGE_SUBSCRIPTION_DETAILS
	SystemSecureSpeculationControlInformation, // SECURE_SPECULATION_CONTROL_INFORMATION
	SystemSpacesBootInformation, // since 20H2
	SystemFwRamdiskInformation, // SYSTEM_FIRMWARE_RAMDISK_INFORMATION
	SystemWheaIpmiHardwareInformation,
	SystemDifSetRuleClassInformation,
	SystemDifClearRuleClassInformation,
	SystemDifApplyPluginVerificationOnDriver,
	SystemDifRemovePluginVerificationOnDriver, // 220
	SystemShadowStackInformation, // SYSTEM_SHADOW_STACK_INFORMATION
	SystemBuildVersionInformation, // SYSTEM_BUILD_VERSION_INFORMATION
	SystemPoolLimitInformation, // SYSTEM_POOL_LIMIT_INFORMATION
	SystemCodeIntegrityAddDynamicStore,
	SystemCodeIntegrityClearDynamicStores,
	SystemDifPoolTrackingInformation,
	SystemPoolZeroingInformation, // SYSTEM_POOL_ZEROING_INFORMATION
	MaxSystemInfoClass
} SYSTEM_INFORMATION_CLASS;

//
// Information Structures for NtQuerySystemInformation
//
typedef struct _SYSTEM_BASIC_INFORMATION
{
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	ULONG_PTR ActiveProcessorsAffinityMask;
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

// Class 1
typedef struct _SYSTEM_PROCESSOR_INFORMATION
{
	USHORT ProcessorArchitecture;
	USHORT ProcessorLevel;
	USHORT ProcessorRevision;
	USHORT Reserved;
	ULONG ProcessorFeatureBits;
} SYSTEM_PROCESSOR_INFORMATION, *PSYSTEM_PROCESSOR_INFORMATION;

// Class 2
typedef struct _SYSTEM_PERFORMANCE_INFORMATION
{
	LARGE_INTEGER IdleProcessTime;
	LARGE_INTEGER IoReadTransferCount;
	LARGE_INTEGER IoWriteTransferCount;
	LARGE_INTEGER IoOtherTransferCount;
	ULONG IoReadOperationCount;
	ULONG IoWriteOperationCount;
	ULONG IoOtherOperationCount;
	ULONG AvailablePages;
	ULONG CommittedPages;
	ULONG CommitLimit;
	ULONG PeakCommitment;
	ULONG PageFaultCount;
	ULONG CopyOnWriteCount;
	ULONG TransitionCount;
	ULONG CacheTransitionCount;
	ULONG DemandZeroCount;
	ULONG PageReadCount;
	ULONG PageReadIoCount;
	ULONG CacheReadCount;
	ULONG CacheIoCount;
	ULONG DirtyPagesWriteCount;
	ULONG DirtyWriteIoCount;
	ULONG MappedPagesWriteCount;
	ULONG MappedWriteIoCount;
	ULONG PagedPoolPages;
	ULONG NonPagedPoolPages;
	ULONG PagedPoolAllocs;
	ULONG PagedPoolFrees;
	ULONG NonPagedPoolAllocs;
	ULONG NonPagedPoolFrees;
	ULONG FreeSystemPtes;
	ULONG ResidentSystemCodePage;
	ULONG TotalSystemDriverPages;
	ULONG TotalSystemCodePages;
	ULONG NonPagedPoolLookasideHits;
	ULONG PagedPoolLookasideHits;
	ULONG Spare3Count;
	ULONG ResidentSystemCachePage;
	ULONG ResidentPagedPoolPage;
	ULONG ResidentSystemDriverPage;
	ULONG CcFastReadNoWait;
	ULONG CcFastReadWait;
	ULONG CcFastReadResourceMiss;
	ULONG CcFastReadNotPossible;
	ULONG CcFastMdlReadNoWait;
	ULONG CcFastMdlReadWait;
	ULONG CcFastMdlReadResourceMiss;
	ULONG CcFastMdlReadNotPossible;
	ULONG CcMapDataNoWait;
	ULONG CcMapDataWait;
	ULONG CcMapDataNoWaitMiss;
	ULONG CcMapDataWaitMiss;
	ULONG CcPinMappedDataCount;
	ULONG CcPinReadNoWait;
	ULONG CcPinReadWait;
	ULONG CcPinReadNoWaitMiss;
	ULONG CcPinReadWaitMiss;
	ULONG CcCopyReadNoWait;
	ULONG CcCopyReadWait;
	ULONG CcCopyReadNoWaitMiss;
	ULONG CcCopyReadWaitMiss;
	ULONG CcMdlReadNoWait;
	ULONG CcMdlReadWait;
	ULONG CcMdlReadNoWaitMiss;
	ULONG CcMdlReadWaitMiss;
	ULONG CcReadAheadIos;
	ULONG CcLazyWriteIos;
	ULONG CcLazyWritePages;
	ULONG CcDataFlushes;
	ULONG CcDataPages;
	ULONG ContextSwitches;
	ULONG FirstLevelTbFills;
	ULONG SecondLevelTbFills;
	ULONG SystemCalls;
} SYSTEM_PERFORMANCE_INFORMATION, *PSYSTEM_PERFORMANCE_INFORMATION;

// Class 3
typedef struct _SYSTEM_TIMEOFDAY_INFORMATION
{
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG TimeZoneId;
	ULONG Reserved;
	LARGE_INTEGER BootTimeBias;
	LARGE_INTEGER SleepTimeBias;
} SYSTEM_TIMEOFDAY_INFORMATION, *PSYSTEM_TIMEOFDAY_INFORMATION;

// Class 4
// This class is obsolete, please use KUSER_SHARED_DATA instead

// Class 5
enum THREAD_STATE
{
	StateInitialized,
	StateReady,
	StateRunning,
	StateStandby,
	StateTerminated,
	StateWait,
	StateTransition
};


typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	THREAD_STATE ThreadState;
	KWAIT_REASON WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct SYSTEM_EXTENDED_THREAD_INFORMATION : SYSTEM_THREAD_INFORMATION
{
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress;
	PVOID Reserved[3];
} *PSYSTEM_EXTENDED_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR PageDirectoryBase;

	//
	// This part corresponds to VM_COUNTERS_EX.
	// NOTE: *NOT* THE SAME AS VM_COUNTERS!
	//
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;

	//
	// This part corresponds to IO_COUNTERS
	//
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;

	SYSTEM_EXTENDED_THREAD_INFORMATION TH[];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

// Class 6
typedef struct _SYSTEM_CALL_COUNT_INFORMATION
{
	ULONG Length;
	ULONG NumberOfTables;
} SYSTEM_CALL_COUNT_INFORMATION, *PSYSTEM_CALL_COUNT_INFORMATION;

// Class 7
typedef struct _SYSTEM_DEVICE_INFORMATION
{
	ULONG NumberOfDisks;
	ULONG NumberOfFloppies;
	ULONG NumberOfCdRoms;
	ULONG NumberOfTapes;
	ULONG NumberOfSerialPorts;
	ULONG NumberOfParallelPorts;
} SYSTEM_DEVICE_INFORMATION, *PSYSTEM_DEVICE_INFORMATION;

// Class 8
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
{
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER DpcTime;
	LARGE_INTEGER InterruptTime;
	ULONG InterruptCount;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, *PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

// Class 9
typedef struct _SYSTEM_FLAGS_INFORMATION
{
	ULONG Flags;
} SYSTEM_FLAGS_INFORMATION, *PSYSTEM_FLAGS_INFORMATION;

// Class 10
typedef struct _SYSTEM_CALL_TIME_INFORMATION
{
	ULONG Length;
	ULONG TotalCalls;
	LARGE_INTEGER TimeOfCalls[];
} SYSTEM_CALL_TIME_INFORMATION, *PSYSTEM_CALL_TIME_INFORMATION;

typedef struct RTL_PROCESS_MODULE_INFORMATION {
	HANDLE Section;                 // Not filled in
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR  FullPathName[ 256 ];
} *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct RTL_PROCESS_MODULES {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[];
} *PRTL_PROCESS_MODULES;

typedef struct RTL_PROCESS_MODULE_INFORMATION32 {
	ULONG Section;                 // Not filled in
	ULONG MappedBase;
	ULONG ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	CHAR  FullPathName[ 256 ];
} *PRTL_PROCESS_MODULE_INFORMATION32;

typedef struct RTL_PROCESS_MODULES32 {
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION32 Modules[];
} *PRTL_PROCESS_MODULES32;

typedef struct _RTL_PROCESS_LOCK_INFORMATION {
	PVOID Address;
	USHORT Type;
	USHORT CreatorBackTraceIndex;

	HANDLE OwningThread;        // from the thread's ClientId->UniqueThread
	LONG LockCount;
	ULONG ContentionCount;
	ULONG EntryCount;

	//
	// The following fields are only valid for Type == RTL_CRITSECT_TYPE
	//

	LONG RecursionCount;

	//
	// The following fields are only valid for Type == RTL_RESOURCE_TYPE
	//

	ULONG NumberOfWaitingShared;
	ULONG NumberOfWaitingExclusive;
} RTL_PROCESS_LOCK_INFORMATION, *PRTL_PROCESS_LOCK_INFORMATION;


typedef struct _RTL_PROCESS_LOCKS {
	ULONG NumberOfLocks;
	RTL_PROCESS_LOCK_INFORMATION Locks[ 1 ];
} RTL_PROCESS_LOCKS, *PRTL_PROCESS_LOCKS;

#define MAX_STACK_DEPTH 32

typedef struct _RTL_PROCESS_BACKTRACE_INFORMATION {
	PCHAR SymbolicBackTrace;        // Not filled in
	ULONG TraceCount;
	USHORT Index;
	USHORT Depth;
	PVOID BackTrace[ MAX_STACK_DEPTH ];
} RTL_PROCESS_BACKTRACE_INFORMATION, *PRTL_PROCESS_BACKTRACE_INFORMATION;

typedef struct _RTL_PROCESS_BACKTRACES {
	ULONG CommittedMemory;
	ULONG ReservedMemory;
	ULONG NumberOfBackTraceLookups;
	ULONG NumberOfBackTraces;
	RTL_PROCESS_BACKTRACE_INFORMATION BackTraces[ 1 ];
} RTL_PROCESS_BACKTRACES, *PRTL_PROCESS_BACKTRACES;

typedef struct _RTL_HEAP_ENTRY {
	SIZE_T Size;
	USHORT Flags;
	USHORT AllocatorBackTraceIndex;
	union {
		struct {
			SIZE_T Settable;
			ULONG Tag;
		} s1;   // All other heap entries
		struct {
			SIZE_T CommittedSize;
			PVOID FirstBlock;
		} s2;   // RTL_SEGMENT
	} u;
} RTL_HEAP_ENTRY, *PRTL_HEAP_ENTRY;

#define RTL_HEAP_BUSY               (USHORT)0x0001
#define RTL_HEAP_SEGMENT            (USHORT)0x0002
#define RTL_HEAP_SETTABLE_VALUE     (USHORT)0x0010
#define RTL_HEAP_SETTABLE_FLAG1     (USHORT)0x0020
#define RTL_HEAP_SETTABLE_FLAG2     (USHORT)0x0040
#define RTL_HEAP_SETTABLE_FLAG3     (USHORT)0x0080
#define RTL_HEAP_SETTABLE_FLAGS     (USHORT)0x00E0
#define RTL_HEAP_UNCOMMITTED_RANGE  (USHORT)0x0100
#define RTL_HEAP_PROTECTED_ENTRY    (USHORT)0x0200

typedef struct _RTL_HEAP_TAG {
	ULONG NumberOfAllocations;
	ULONG NumberOfFrees;
	SIZE_T BytesAllocated;
	USHORT TagIndex;
	USHORT CreatorBackTraceIndex;
	WCHAR TagName[ 24 ];
} RTL_HEAP_TAG, *PRTL_HEAP_TAG;

typedef struct _RTL_HEAP_INFORMATION {
	PVOID BaseAddress;
	ULONG Flags;
	USHORT EntryOverhead;
	USHORT CreatorBackTraceIndex;
	SIZE_T BytesAllocated;
	SIZE_T BytesCommitted;
	ULONG NumberOfTags;
	ULONG NumberOfEntries;
	ULONG NumberOfPseudoTags;
	ULONG PseudoTagGranularity;
	ULONG Reserved[ 5 ];
	PRTL_HEAP_TAG Tags;
	PRTL_HEAP_ENTRY Entries;
} RTL_HEAP_INFORMATION, *PRTL_HEAP_INFORMATION;

typedef struct _RTL_PROCESS_HEAPS {
	ULONG NumberOfHeaps;
	RTL_HEAP_INFORMATION Heaps[ 1 ];
} RTL_PROCESS_HEAPS, *PRTL_PROCESS_HEAPS;

//
// Debugging support
//

typedef struct _RTL_DEBUG_INFORMATION {
	HANDLE SectionHandleClient;
	PVOID ViewBaseClient;
	PVOID ViewBaseTarget;
	ULONG_PTR ViewBaseDelta;
	HANDLE EventPairClient;
	HANDLE EventPairTarget;
	HANDLE TargetProcessId;
	HANDLE TargetThreadHandle;
	ULONG Flags;
	SIZE_T OffsetFree;
	SIZE_T CommitSize;
	SIZE_T ViewSize;
	PRTL_PROCESS_MODULES Modules;
	PRTL_PROCESS_BACKTRACES BackTraces;
	PRTL_PROCESS_HEAPS Heaps;
	PRTL_PROCESS_LOCKS Locks;
	PVOID SpecificHeap;
	HANDLE TargetProcessHandle;
	PVOID Reserved[ 6 ];
} RTL_DEBUG_INFORMATION, *PRTL_DEBUG_INFORMATION;

#define RTL_QUERY_PROCESS_MODULES       0x00000001
#define RTL_QUERY_PROCESS_BACKTRACES    0x00000002
#define RTL_QUERY_PROCESS_HEAP_SUMMARY  0x00000004
#define RTL_QUERY_PROCESS_HEAP_TAGS     0x00000008
#define RTL_QUERY_PROCESS_HEAP_ENTRIES  0x00000010
#define RTL_QUERY_PROCESS_LOCKS         0x00000020
#define RTL_QUERY_PROCESS_MODULES32     0x00000040
#define RTL_QUERY_PROCESS_NONINVASIVE   0x80000000

struct MEMORY_WORKING_SET_LIST
{
	ULONG	NumberOfPages;
	ULONG_PTR	WorkingSetList[0];
};

#define  LDRP_STATIC_LINK				0x00000002
#define  LDRP_IMAGE_DLL					0x00000004
#define  LDRP_LOAD_IN_PROGRESS			0x00001000
#define  LDRP_UNLOAD_IN_PROGRES			0x00002000
#define  LDRP_ENTRY_PROCESSED			0x00004000
#define  LDRP_ENTRY_INSERTED			0x00008000
#define  LDRP_CURRENT_LOAD				0x00010000
#define  LDRP_FAIL_BUILTIN_LOAD			0x00020000
#define  LDRP_DONT_CALL_FOR_THREADS		0x00040000
#define  LDRP_PROCESS_ATTACH_CALLED		0x00080000
#define  LDRP_DEBUG_SYMBOL_LOADED		0x00100000
#define	 LDRP_IMAGE_NOT_AT_BASE			0x00200000
#define	 LDRP_IMAGE_CLR					0x00400000
#define	 LDRP_IMAGE_REDIRECTED			0x10000000

enum WSLE
{
	WSLE_READONLY = 1,
	WSLE_EXECUTE,
	WSLE_EXECUTE_READ,
	WSLE_READWRITE,
	WSLE_WRITECOPY,
	WSLE_EXECUTE_READWRITE,
	WSLE_EXECUTE_WRITECOPY,
	WSLE_PROTECT_MASK = 7,
	WSLE_SHARE_COUNT_MASK = 0xe0,
	WSLE_SHARE_COUNT_SHIFT = 5,
	WSLE_SHAREABLE = 0x100
};

// Class 12 - See RTL_PROCESS_LOCKS

// Class 13 - See RTL_PROCESS_BACKTRACES

// Class 14 - 15
typedef struct _SYSTEM_POOL_ENTRY
{
	BOOLEAN Allocated;
	BOOLEAN Spare0;
	USHORT AllocatorBackTraceIndex;
	ULONG Size;
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
		PVOID ProcessChargedQuota;
	};
} SYSTEM_POOL_ENTRY, *PSYSTEM_POOL_ENTRY;

typedef struct _SYSTEM_POOL_INFORMATION
{
	ULONG TotalSize;
	PVOID FirstEntry;
	USHORT EntryOverhead;
	BOOLEAN PoolTagPresent;
	BOOLEAN Spare0;
	ULONG NumberOfEntries;
	SYSTEM_POOL_ENTRY Entries[];
} SYSTEM_POOL_INFORMATION, *PSYSTEM_POOL_INFORMATION;

// Class 16
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG  HandleAttributes;
	ULONG  Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[  ];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
// Class 17
typedef struct _SYSTEM_OBJECTTYPE_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfObjects;
	ULONG NumberOfHandles;
	ULONG TypeIndex;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	ULONG PoolType;
	BOOLEAN SecurityRequired;
	BOOLEAN WaitableObject;
	UNICODE_STRING TypeName;
} SYSTEM_OBJECTTYPE_INFORMATION, *PSYSTEM_OBJECTTYPE_INFORMATION;

typedef struct _SYSTEM_OBJECT_INFORMATION
{
	ULONG NextEntryOffset;
	PVOID Object;
	HANDLE CreatorUniqueProcess;
	USHORT CreatorBackTraceIndex;
	USHORT Flags;
	LONG PointerCount;
	LONG HandleCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	HANDLE ExclusiveProcessId;
	PVOID SecurityDescriptor;
	OBJECT_NAME_INFORMATION NameInfo;
} SYSTEM_OBJECT_INFORMATION, *PSYSTEM_OBJECT_INFORMATION;

// Class 18
typedef struct _SYSTEM_PAGEFILE_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG TotalSize;
	ULONG TotalInUse;
	ULONG PeakUsage;
	UNICODE_STRING PageFileName;
} SYSTEM_PAGEFILE_INFORMATION, *PSYSTEM_PAGEFILE_INFORMATION;

// Class 19
typedef struct _SYSTEM_VDM_INSTEMUL_INFO
{
	ULONG SegmentNotPresent;
	ULONG VdmOpcode0F;
	ULONG OpcodeESPrefix;
	ULONG OpcodeCSPrefix;
	ULONG OpcodeSSPrefix;
	ULONG OpcodeDSPrefix;
	ULONG OpcodeFSPrefix;
	ULONG OpcodeGSPrefix;
	ULONG OpcodeOPER32Prefix;
	ULONG OpcodeADDR32Prefix;
	ULONG OpcodeINSB;
	ULONG OpcodeINSW;
	ULONG OpcodeOUTSB;
	ULONG OpcodeOUTSW;
	ULONG OpcodePUSHF;
	ULONG OpcodePOPF;
	ULONG OpcodeINTnn;
	ULONG OpcodeINTO;
	ULONG OpcodeIRET;
	ULONG OpcodeINBimm;
	ULONG OpcodeINWimm;
	ULONG OpcodeOUTBimm;
	ULONG OpcodeOUTWimm ;
	ULONG OpcodeINB;
	ULONG OpcodeINW;
	ULONG OpcodeOUTB;
	ULONG OpcodeOUTW;
	ULONG OpcodeLOCKPrefix;
	ULONG OpcodeREPNEPrefix;
	ULONG OpcodeREPPrefix;
	ULONG OpcodeHLT;
	ULONG OpcodeCLI;
	ULONG OpcodeSTI;
	ULONG BopCount;
} SYSTEM_VDM_INSTEMUL_INFO, *PSYSTEM_VDM_INSTEMUL_INFO;

// Class 20 - ULONG VDMBOPINFO

// Class 21
typedef struct _SYSTEM_FILECACHE_INFORMATION
{
	ULONG CurrentSize;
	ULONG PeakSize;
	ULONG PageFaultCount;
	ULONG MinimumWorkingSet;
	ULONG MaximumWorkingSet;
	ULONG CurrentSizeIncludingTransitionInPages;
	ULONG PeakSizeIncludingTransitionInPages;
	ULONG TransitionRePurposeCount;
	ULONG Flags;
} SYSTEM_FILECACHE_INFORMATION, *PSYSTEM_FILECACHE_INFORMATION;

// Class 22
typedef struct _SYSTEM_POOLTAG
{
	union
	{
		UCHAR Tag[4];
		ULONG TagUlong;
	};
	ULONG PagedAllocs;
	ULONG PagedFrees;
	ULONG PagedUsed;
	ULONG NonPagedAllocs;
	ULONG NonPagedFrees;
	ULONG NonPagedUsed;
} SYSTEM_POOLTAG, *PSYSTEM_POOLTAG;
typedef struct _SYSTEM_POOLTAG_INFORMATION
{
	ULONG Count;
	SYSTEM_POOLTAG TagInfo[];
} SYSTEM_POOLTAG_INFORMATION, *PSYSTEM_POOLTAG_INFORMATION;

// Class 23
typedef struct _SYSTEM_INTERRUPT_INFORMATION
{
	ULONG ContextSwitches;
	ULONG DpcCount;
	ULONG DpcRate;
	ULONG TimeIncrement;
	ULONG DpcBypassCount;
	ULONG ApcBypassCount;
} SYSTEM_INTERRUPT_INFORMATION, *PSYSTEM_INTERRUPT_INFORMATION;

// Class 24
typedef struct _SYSTEM_DPC_BEHAVIOR_INFORMATION
{
	ULONG Spare;
	ULONG DpcQueueDepth;
	ULONG MinimumDpcRate;
	ULONG AdjustDpcThreshold;
	ULONG IdealDpcRate;
} SYSTEM_DPC_BEHAVIOR_INFORMATION, *PSYSTEM_DPC_BEHAVIOR_INFORMATION;

// Class 25
typedef struct _SYSTEM_MEMORY_INFO
{
	PUCHAR StringOffset;
	USHORT ValidCount;
	USHORT TransitionCount;
	USHORT ModifiedCount;
	USHORT PageTableCount;
} SYSTEM_MEMORY_INFO, *PSYSTEM_MEMORY_INFO;

typedef struct _SYSTEM_MEMORY_INFORMATION
{
	ULONG InfoSize;
	ULONG StringStart;
	SYSTEM_MEMORY_INFO Memory[];
} SYSTEM_MEMORY_INFORMATION, *PSYSTEM_MEMORY_INFORMATION;

// Class 26
typedef struct _SYSTEM_GDI_DRIVER_INFORMATION
{
	UNICODE_STRING DriverName;
	PVOID ImageAddress;
	PVOID SectionPointer;
	PVOID EntryPoint;
	PIMAGE_EXPORT_DIRECTORY ExportSectionPointer;
	ULONG ImageLength;
} SYSTEM_GDI_DRIVER_INFORMATION, *PSYSTEM_GDI_DRIVER_INFORMATION;

// Class 27
// Not an actually class, simply a PVOID to the SectionPointer

// Class 28
typedef struct _SYSTEM_QUERY_TIME_ADJUST_INFORMATION
{
	ULONG TimeAdjustment;
	ULONG TimeIncrement;
	BOOLEAN Enable;
} SYSTEM_QUERY_TIME_ADJUST_INFORMATION, *PSYSTEM_QUERY_TIME_ADJUST_INFORMATION;

typedef struct _SYSTEM_SET_TIME_ADJUST_INFORMATION
{
	ULONG TimeAdjustment;
	BOOLEAN Enable;
} SYSTEM_SET_TIME_ADJUST_INFORMATION, *PSYSTEM_SET_TIME_ADJUST_INFORMATION;

// Class 29 - Same as 25

// FIXME: Class 30

// Class 31
typedef struct _SYSTEM_REF_TRACE_INFORMATION
{
	UCHAR TraceEnable;
	UCHAR TracePermanent;
	UNICODE_STRING TraceProcessName;
	UNICODE_STRING TracePoolTags;
} SYSTEM_REF_TRACE_INFORMATION, *PSYSTEM_REF_TRACE_INFORMATION;

// Class 32 - OBSOLETE

// Class 33
typedef struct _SYSTEM_EXCEPTION_INFORMATION
{
	ULONG AlignmentFixupCount;
	ULONG ExceptionDispatchCount;
	ULONG FloatingEmulationCount;
	ULONG ByteWordEmulationCount;
} SYSTEM_EXCEPTION_INFORMATION, *PSYSTEM_EXCEPTION_INFORMATION;

// Class 34
typedef struct _SYSTEM_CRASH_STATE_INFORMATION
{
	ULONG ValidCrashDump;
} SYSTEM_CRASH_STATE_INFORMATION, *PSYSTEM_CRASH_STATE_INFORMATION;

// Class 35
typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN KernelDebuggerEnabled;
	BOOLEAN KernelDebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

// Class 36
typedef struct _SYSTEM_CONTEXT_SWITCH_INFORMATION
{
	ULONG ContextSwitches;
	ULONG FindAny;
	ULONG FindLast;
	ULONG FindIdeal;
	ULONG IdleAny;
	ULONG IdleCurrent;
	ULONG IdleLast;
	ULONG IdleIdeal;
	ULONG PreemptAny;
	ULONG PreemptCurrent;
	ULONG PreemptLast;
	ULONG SwitchToIdle;
} SYSTEM_CONTEXT_SWITCH_INFORMATION, *PSYSTEM_CONTEXT_SWITCH_INFORMATION;

// Class 37
typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION
{
	ULONG RegistryQuotaAllowed;
	ULONG RegistryQuotaUsed;
	ULONG PagedPoolSize;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, *PSYSTEM_REGISTRY_QUOTA_INFORMATION;

// Class 38
// Not a structure, simply send the UNICODE_STRING

// Class 39
// Not a structure, simply send a ULONG containing the new separation

// Class 40
//typedef struct _SYSTEM_PLUGPLAY_BUS_INFORMATION
//{
//	ULONG BusCount;
//	PLUGPLAY_BUS_INSTANCE BusInstance[];
//} SYSTEM_PLUGPLAY_BUS_INFORMATION, *PSYSTEM_PLUGPLAY_BUS_INFORMATION;

// Class 41
//typedef struct _SYSTEM_DOCK_INFORMATION
//{
//	SYSTEM_DOCK_STATE DockState;
//	INTERFACE_TYPE DeviceBusType;
//	ULONG DeviceBusNumber;
//	ULONG SlotNumber;
//} SYSTEM_DOCK_INFORMATION, *PSYSTEM_DOCK_INFORMATION;

// Class 42
typedef struct _SYSTEM_POWER_INFORMATION_NATIVE
{
	BOOLEAN SystemSuspendSupported;
	BOOLEAN SystemHibernateSupported;
	BOOLEAN ResumeTimerSupportsSuspend;
	BOOLEAN ResumeTimerSupportsHibernate;
	BOOLEAN LidSupported;
	BOOLEAN TurboSettingSupported;
	BOOLEAN TurboMode;
	BOOLEAN SystemAcOrDc;
	BOOLEAN PowerDownDisabled;
	LARGE_INTEGER SpindownDrives;
} SYSTEM_POWER_INFORMATION_NATIVE, *PSYSTEM_POWER_INFORMATION_NATIVE;

// Class 43
//typedef struct _SYSTEM_LEGACY_DRIVER_INFORMATION
//{
//	PNP_VETO_TYPE VetoType;
//	UNICODE_STRING VetoDriver;
//	// CHAR Buffer[0];
//} SYSTEM_LEGACY_DRIVER_INFORMATION, *PSYSTEM_LEGACY_DRIVER_INFORMATION;

// Class 44
//typedef struct _TIME_ZONE_INFORMATION RTL_TIME_ZONE_INFORMATION;

// Class 45
typedef struct _SYSTEM_LOOKASIDE_INFORMATION
{
	USHORT CurrentDepth;
	USHORT MaximumDepth;
	ULONG TotalAllocates;
	ULONG AllocateMisses;
	ULONG TotalFrees;
	ULONG FreeMisses;
	ULONG Type;
	ULONG Tag;
	ULONG Size;
} SYSTEM_LOOKASIDE_INFORMATION, *PSYSTEM_LOOKASIDE_INFORMATION;

// Class 46
// Not a structure. Only a HANDLE for the SlipEvent;

// Class 47
// Not a structure. Only a ULONG for the SessionId;

// Class 48
// Not a structure. Only a ULONG for the SessionId;

// FIXME: Class 49

// Class 50
// Not a structure. Only a ULONG_PTR for the SystemRangeStart

// Class 51
typedef struct _SYSTEM_VERIFIER_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG Level;
	UNICODE_STRING DriverName;
	ULONG RaiseIrqls;
	ULONG AcquireSpinLocks;
	ULONG SynchronizeExecutions;
	ULONG AllocationsAttempted;
	ULONG AllocationsSucceeded;
	ULONG AllocationsSucceededSpecialPool;
	ULONG AllocationsWithNoTag;
	ULONG TrimRequests;
	ULONG Trims;
	ULONG AllocationsFailed;
	ULONG AllocationsFailedDeliberately;
	ULONG Loads;
	ULONG Unloads;
	ULONG UnTrackedPool;
	ULONG CurrentPagedPoolAllocations;
	ULONG CurrentNonPagedPoolAllocations;
	ULONG PeakPagedPoolAllocations;
	ULONG PeakNonPagedPoolAllocations;
	ULONG PagedPoolUsageInBytes;
	ULONG NonPagedPoolUsageInBytes;
	ULONG PeakPagedPoolUsageInBytes;
	ULONG PeakNonPagedPoolUsageInBytes;
} SYSTEM_VERIFIER_INFORMATION, *PSYSTEM_VERIFIER_INFORMATION;

// FIXME: Class 52

// Class 53
typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
	ULONG SessionId;
	ULONG SizeOfBuf;
	PVOID Buffer; // Same format as in SystemProcessInformation
} SYSTEM_SESSION_PROCESS_INFORMATION, *PSYSTEM_SESSION_PROCESS_INFORMATION;

// FIXME: Class 54-97

//
// Hotpatch flags
//
#define RTL_HOTPATCH_SUPPORTED_FLAG         0x01
#define RTL_HOTPATCH_SWAP_OBJECT_NAMES      0x08 << 24
#define RTL_HOTPATCH_SYNC_RENAME_FILES      0x10 << 24
#define RTL_HOTPATCH_PATCH_USER_MODE        0x20 << 24
#define RTL_HOTPATCH_REMAP_SYSTEM_DLL       0x40 << 24
#define RTL_HOTPATCH_PATCH_KERNEL_MODE      0x80 << 24


// Class 69
typedef struct _SYSTEM_HOTPATCH_CODE_INFORMATION
{
	ULONG Flags;
	ULONG InfoSize;
	union
	{
		struct
		{
			ULONG Foo;
		} CodeInfo;
		struct
		{
			USHORT NameOffset;
			USHORT NameLength;
		} KernelInfo;
		struct
		{
			USHORT NameOffset;
			USHORT NameLength;
			USHORT TargetNameOffset;
			USHORT TargetNameLength;
			UCHAR PatchingFinished;
		} UserModeInfo;
		struct
		{
			USHORT NameOffset;
			USHORT NameLength;
			USHORT TargetNameOffset;
			USHORT TargetNameLength;
			UCHAR PatchingFinished;
			NTSTATUS ReturnCode;
			HANDLE TargetProcess;
		} InjectionInfo;
		struct
		{
			HANDLE FileHandle1;
			PIO_STATUS_BLOCK IoStatusBlock1;
			PVOID RenameInformation1;
			PVOID RenameInformationLength1;
			HANDLE FileHandle2;
			PIO_STATUS_BLOCK IoStatusBlock2;
			PVOID RenameInformation2;
			PVOID RenameInformationLength2;
		} RenameInfo;
		struct
		{
			HANDLE ParentDirectory;
			HANDLE ObjectHandle1;
			HANDLE ObjectHandle2;
		} AtomicSwap;
	};
} SYSTEM_HOTPATCH_CODE_INFORMATION, *PSYSTEM_HOTPATCH_CODE_INFORMATION;

//enum _MEMORY_INFORMATION_CLASS
//{
//	MemoryBasicInformation,
//	MemoryWorkingSetList,
//	MemorySectionName,
//	MemoryBasicVlmInformation
//};

// ++ntobjapi.h

typedef struct _OBJECT_BASIC_INFORMATION
{
	ULONG Attributes;
	ACCESS_MASK GrantedAccess;
	ULONG HandleCount;
	ULONG PointerCount;
	ULONG PagedPoolCharge;
	ULONG NonPagedPoolCharge;
	ULONG Reserved[3];
	ULONG NameInfoSize;
	ULONG TypeInfoSize;
	ULONG SecurityDescriptorSize;
	LARGE_INTEGER CreationTime;
} OBJECT_BASIC_INFORMATION, *POBJECT_BASIC_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccessMask;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	UCHAR TypeIndex; // since WINBLUE
	CHAR ReservedByte;
	ULONG PoolType;
	ULONG DefaultPagedPoolCharge;
	ULONG DefaultNonPagedPoolCharge;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

typedef struct _OBJECT_TYPES_INFORMATION
{
	ULONG NumberOfTypes;
	OBJECT_TYPE_INFORMATION TypeInformation[];
} OBJECT_TYPES_INFORMATION, *POBJECT_TYPES_INFORMATION;

typedef struct _OBJECT_HANDLE_FLAG_INFORMATION
{
	BOOLEAN Inherit;
	BOOLEAN ProtectFromClose;
} OBJECT_HANDLE_FLAG_INFORMATION, *POBJECT_HANDLE_FLAG_INFORMATION;

typedef struct _OBJECT_DIRECTORY_INFORMATION
{
	UNICODE_STRING Name;
	UNICODE_STRING TypeName;
} OBJECT_DIRECTORY_INFORMATION, *POBJECT_DIRECTORY_INFORMATION;

// --ntobjapi.h

enum SECTION_INFORMATION_CLASS
{
	SectionBasicInformation,
	SectionImageInformation
};

struct SECTION_BASIC_INFORMATION
{
	LPVOID BaseAddress;
	ULONG Attributes;
	LARGE_INTEGER Size;
};

struct SECTION_IMAGE_INFORMATION
{
	PVOID TransferAddress;
	ULONG ZeroBits;
	SIZE_T MaximumStackSize;
	SIZE_T CommittedStackSize;
	ULONG SubSystemType;
	union
	{
		struct
		{
			USHORT SubSystemMinorVersion;
			USHORT SubSystemMajorVersion;
		};
		ULONG SubSystemVersion;
	};
	ULONG GpValue;
	USHORT ImageCharacteristics;
	USHORT DllCharacteristics;
	USHORT Machine;
	BOOLEAN ImageContainsCode;
	union
	{
		UCHAR ImageFlags;
		struct
		{
			UCHAR ComPlusNativeReady : 1;
			UCHAR ComPlusILOnly : 1;
			UCHAR ImageDynamicallyRelocated : 1;
			UCHAR ImageMappedFlat : 1;
			UCHAR BaseBelow4gb : 1;
			UCHAR Reserved : 3;
		};
	};
	ULONG LoaderFlags;
	ULONG ImageFileSize;
	ULONG CheckSum;
};

// Thread information structures

typedef struct _THREAD_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PTEB TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG_PTR AffinityMask;
	KPRIORITY Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION, *PTHREAD_BASIC_INFORMATION;

// private
typedef struct _THREAD_LAST_SYSCALL_INFORMATION
{
	PVOID FirstArgument;
	USHORT SystemCallNumber;
} THREAD_LAST_SYSCALL_INFORMATION, *PTHREAD_LAST_SYSCALL_INFORMATION;

// private
typedef struct _THREAD_CYCLE_TIME_INFORMATION
{
	ULONGLONG AccumulatedCycles;
	ULONGLONG CurrentCycleCount;
} THREAD_CYCLE_TIME_INFORMATION, *PTHREAD_CYCLE_TIME_INFORMATION;

// private
typedef struct _THREAD_TEB_INFORMATION
{
	PVOID TebInformation; // buffer to place data in
	ULONG TebOffset; // offset in TEB to begin reading from
	ULONG BytesToRead; // number of bytes to read
} THREAD_TEB_INFORMATION, *PTHREAD_TEB_INFORMATION;

// symbols
typedef struct _COUNTER_READING
{
	HARDWARE_COUNTER_TYPE Type;
	ULONG Index;
	ULONG64 Start;
	ULONG64 Total;
} COUNTER_READING, *PCOUNTER_READING;

// symbols
typedef struct _THREAD_PERFORMANCE_DATA
{
	USHORT Size;
	USHORT Version;
	PROCESSOR_NUMBER ProcessorNumber;
	ULONG ContextSwitches;
	ULONG HwCountersCount;
	ULONG64 UpdateCount;
	ULONG64 WaitReasonBitMap;
	ULONG64 HardwareCounters;
	COUNTER_READING CycleTime;
	COUNTER_READING HwCounters[MAX_HW_COUNTERS];
} THREAD_PERFORMANCE_DATA, *PTHREAD_PERFORMANCE_DATA;

// private
typedef struct _THREAD_PROFILING_INFORMATION
{
	ULONG64 HardwareCounters;
	ULONG Flags;
	ULONG Enable;
	PTHREAD_PERFORMANCE_DATA PerformanceData;
} THREAD_PROFILING_INFORMATION, *PTHREAD_PROFILING_INFORMATION;

enum LPC_TYPE
{
	LPC_NEW_MESSAGE,
	LPC_REQUEST,
	LPC_REPLY,
	LPC_DATAGRAM,
	LPC_LOST_REPLAY,
	LPC_PORT_CLOSED,
	LPC_CLIENT_DIED,
	LPC_EXCEPTION,
	LPC_DEBUG_EVENT,
	LPC_ERROR_EVENT,
	LPC_CONNECTION_REQUEST
};

enum CHANCE : char
{ 
	FirstChance, 
	LastChance
};

enum EVENT 
{
	ExceptionEvent, 
	DebugEvent
};

enum DEBUG_SERVICE_CODE
{
	DebugPrint = 1,
	DebugPromt,
	DebugLoadImageSymbols,
	DebugUnLoadImageSymbols
};

//////////////////////////////////////////////////////////////////////////
// ps
typedef enum _PS_PROTECTED_TYPE
{
	PsProtectedTypeNone,
	PsProtectedTypeProtectedLight,
	PsProtectedTypeProtected,
	PsProtectedTypeMax
} PS_PROTECTED_TYPE;

typedef enum _PS_PROTECTED_SIGNER
{
	PsProtectedSignerNone,
	PsProtectedSignerAuthenticode,
	PsProtectedSignerCodeGen,
	PsProtectedSignerAntimalware,
	PsProtectedSignerLsa,
	PsProtectedSignerWindows,
	PsProtectedSignerWinTcb,
	PsProtectedSignerWinSystem,
	PsProtectedSignerApp,
	PsProtectedSignerMax
} PS_PROTECTED_SIGNER;

typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;
		struct
		{
			UCHAR Type : 3;
			UCHAR Audit : 1;
			UCHAR Signer : 4;
		};
	};
} PS_PROTECTION, *PPS_PROTECTION;

// Time zones

typedef struct _RTL_TIME_ZONE_INFORMATION
{
	LONG Bias;
	WCHAR StandardName[32];
	TIME_FIELDS StandardStart;
	LONG StandardBias;
	WCHAR DaylightName[32];
	TIME_FIELDS DaylightStart;
	LONG DaylightBias;
} RTL_TIME_ZONE_INFORMATION, *PRTL_TIME_ZONE_INFORMATION;

NTSYSAPI
NTSTATUS
NTAPI
RtlQueryTimeZoneInformation(
							_Out_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
							);

NTSYSAPI
NTSTATUS
NTAPI
RtlSetTimeZoneInformation(
						  _In_ PRTL_TIME_ZONE_INFORMATION TimeZoneInformation
						  );

