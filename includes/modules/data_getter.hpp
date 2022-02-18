#ifndef WNDHIJACK_MODULE_GETTER_HPP
#define WNDHIJACK_MODULE_GETTER_HPP

#include <defs/nt.hpp>
#include <defs/smart.hpp>
#include <ntstrsafe.h>
#include <ntddmou.h>

namespace IDontLikeBlue
{
#pragma once

	typedef enum _SYSTEM_INFORMATION_CLASS
	{
		SystemBasicInformation = 0x0,
		SystemProcessorInformation = 0x1,
		SystemPerformanceInformation = 0x2,
		SystemTimeOfDayInformation = 0x3,
		SystemPathInformation = 0x4,
		SystemProcessInformation = 0x5,
		SystemCallCountInformation = 0x6,
		SystemDeviceInformation = 0x7,
		SystemProcessorPerformanceInformation = 0x8,
		SystemFlagsInformation = 0x9,
		SystemCallTimeInformation = 0xa,
		SystemModuleInformation = 0xb,
		SystemLocksInformation = 0xc,
		SystemStackTraceInformation = 0xd,
		SystemPagedPoolInformation = 0xe,
		SystemNonPagedPoolInformation = 0xf,
		SystemHandleInformation = 0x10,
		SystemObjectInformation = 0x11,
		SystemPageFileInformation = 0x12,
		SystemVdmInstemulInformation = 0x13,
		SystemVdmBopInformation = 0x14,
		SystemFileCacheInformation = 0x15,
		SystemPoolTagInformation = 0x16,
		SystemInterruptInformation = 0x17,
		SystemDpcBehaviorInformation = 0x18,
		SystemFullMemoryInformation = 0x19,
		SystemLoadGdiDriverInformation = 0x1a,
		SystemUnloadGdiDriverInformation = 0x1b,
		SystemTimeAdjustmentInformation = 0x1c,
		SystemSummaryMemoryInformation = 0x1d,
		SystemMirrorMemoryInformation = 0x1e,
		SystemPerformanceTraceInformation = 0x1f,
		SystemObsolete0 = 0x20,
		SystemExceptionInformation = 0x21,
		SystemCrashDumpStateInformation = 0x22,
		SystemKernelDebuggerInformation = 0x23,
		SystemContextSwitchInformation = 0x24,
		SystemRegistryQuotaInformation = 0x25,
		SystemExtendServiceTableInformation = 0x26,
		SystemPrioritySeperation = 0x27,
		SystemVerifierAddDriverInformation = 0x28,
		SystemVerifierRemoveDriverInformation = 0x29,
		SystemProcessorIdleInformation = 0x2a,
		SystemLegacyDriverInformation = 0x2b,
		SystemCurrentTimeZoneInformation = 0x2c,
		SystemLookasideInformation = 0x2d,
		SystemTimeSlipNotification = 0x2e,
		SystemSessionCreate = 0x2f,
		SystemSessionDetach = 0x30,
		SystemSessionInformation = 0x31,
		SystemRangeStartInformation = 0x32,
		SystemVerifierInformation = 0x33,
		SystemVerifierThunkExtend = 0x34,
		SystemSessionProcessInformation = 0x35,
		SystemLoadGdiDriverInSystemSpace = 0x36,
		SystemNumaProcessorMap = 0x37,
		SystemPrefetcherInformation = 0x38,
		SystemExtendedProcessInformation = 0x39,
		SystemRecommendedSharedDataAlignment = 0x3a,
		SystemComPlusPackage = 0x3b,
		SystemNumaAvailableMemory = 0x3c,
		SystemProcessorPowerInformation = 0x3d,
		SystemEmulationBasicInformation = 0x3e,
		SystemEmulationProcessorInformation = 0x3f,
		SystemExtendedHandleInformation = 0x40,
		SystemLostDelayedWriteInformation = 0x41,
		SystemBigPoolInformation = 0x42,
		SystemSessionPoolTagInformation = 0x43,
		SystemSessionMappedViewInformation = 0x44,
		SystemHotpatchInformation = 0x45,
		SystemObjectSecurityMode = 0x46,
		SystemWatchdogTimerHandler = 0x47,
		SystemWatchdogTimerInformation = 0x48,
		SystemLogicalProcessorInformation = 0x49,
		SystemWow64SharedInformationObsolete = 0x4a,
		SystemRegisterFirmwareTableInformationHandler = 0x4b,
		SystemFirmwareTableInformation = 0x4c,
		SystemModuleInformationEx = 0x4d,
		SystemVerifierTriageInformation = 0x4e,
		SystemSuperfetchInformation = 0x4f,
		SystemMemoryListInformation = 0x50,
		SystemFileCacheInformationEx = 0x51,
		SystemThreadPriorityClientIdInformation = 0x52,
		SystemProcessorIdleCycleTimeInformation = 0x53,
		SystemVerifierCancellationInformation = 0x54,
		SystemProcessorPowerInformationEx = 0x55,
		SystemRefTraceInformation = 0x56,
		SystemSpecialPoolInformation = 0x57,
		SystemProcessIdInformation = 0x58,
		SystemErrorPortInformation = 0x59,
		SystemBootEnvironmentInformation = 0x5a,
		SystemHypervisorInformation = 0x5b,
		SystemVerifierInformationEx = 0x5c,
		SystemTimeZoneInformation = 0x5d,
		SystemImageFileExecutionOptionsInformation = 0x5e,
		SystemCoverageInformation = 0x5f,
		SystemPrefetchPatchInformation = 0x60,
		SystemVerifierFaultsInformation = 0x61,
		SystemSystemPartitionInformation = 0x62,
		SystemSystemDiskInformation = 0x63,
		SystemProcessorPerformanceDistribution = 0x64,
		SystemNumaProximityNodeInformation = 0x65,
		SystemDynamicTimeZoneInformation = 0x66,
		SystemCodeIntegrityInformation = 0x67,
		SystemProcessorMicrocodeUpdateInformation = 0x68,
		SystemProcessorBrandString = 0x69,
		SystemVirtualAddressInformation = 0x6a,
		SystemLogicalProcessorAndGroupInformation = 0x6b,
		SystemProcessorCycleTimeInformation = 0x6c,
		SystemStoreInformation = 0x6d,
		SystemRegistryAppendString = 0x6e,
		SystemAitSamplingValue = 0x6f,
		SystemVhdBootInformation = 0x70,
		SystemCpuQuotaInformation = 0x71,
		SystemNativeBasicInformation = 0x72,
		SystemErrorPortTimeouts = 0x73,
		SystemLowPriorityIoInformation = 0x74,
		SystemBootEntropyInformation = 0x75,
		SystemVerifierCountersInformation = 0x76,
		SystemPagedPoolInformationEx = 0x77,
		SystemSystemPtesInformationEx = 0x78,
		SystemNodeDistanceInformation = 0x79,
		SystemAcpiAuditInformation = 0x7a,
		SystemBasicPerformanceInformation = 0x7b,
		SystemQueryPerformanceCounterInformation = 0x7c,
		SystemSessionBigPoolInformation = 0x7d,
		SystemBootGraphicsInformation = 0x7e,
		SystemScrubPhysicalMemoryInformation = 0x7f,
		SystemBadPageInformation = 0x80,
		SystemProcessorProfileControlArea = 0x81,
		SystemCombinePhysicalMemoryInformation = 0x82,
		SystemEntropyInterruptTimingInformation = 0x83,
		SystemConsoleInformation = 0x84,
		SystemPlatformBinaryInformation = 0x85,
		SystemThrottleNotificationInformation = 0x86,
		SystemHypervisorProcessorCountInformation = 0x87,
		SystemDeviceDataInformation = 0x88,
		SystemDeviceDataEnumerationInformation = 0x89,
		SystemMemoryTopologyInformation = 0x8a,
		SystemMemoryChannelInformation = 0x8b,
		SystemBootLogoInformation = 0x8c,
		SystemProcessorPerformanceInformationEx = 0x8d,
		SystemSpare0 = 0x8e,
		SystemSecureBootPolicyInformation = 0x8f,
		SystemPageFileInformationEx = 0x90,
		SystemSecureBootInformation = 0x91,
		SystemEntropyInterruptTimingRawInformation = 0x92,
		SystemPortableWorkspaceEfiLauncherInformation = 0x93,
		SystemFullProcessInformation = 0x94,
		SystemKernelDebuggerInformationEx = 0x95,
		SystemBootMetadataInformation = 0x96,
		SystemSoftRebootInformation = 0x97,
		SystemElamCertificateInformation = 0x98,
		SystemOfflineDumpConfigInformation = 0x99,
		SystemProcessorFeaturesInformation = 0x9a,
		SystemRegistryReconciliationInformation = 0x9b,
		MaxSystemInfoClass = 0x9c,
	} SYSTEM_INFORMATION_CLASS;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;         // Not filled in
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	typedef struct _SYSTEM_MODULE   // Information Class 11
	{
		ULONG_PTR Reserved[2];
		PVOID Base;
		ULONG Size;
		ULONG Flags;
		USHORT Index;
		USHORT Unknown;
		USHORT LoadCount;
		USHORT ModuleNameOffset;
		CHAR ImageName[256];
	} SYSTEM_MODULE, * PSYSTEM_MODULE;

	typedef struct _SYSTEM_MODULE_INFORMATION   // Information Class 11
	{
		ULONG_PTR ulModuleCount;
		SYSTEM_MODULE Modules[1];
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	struct piddbcache
	{
		LIST_ENTRY		List;
		UNICODE_STRING	DriverName;
		ULONG			TimeDateStamp;
		NTSTATUS		LoadStatus;
		char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
	};

	extern "C" extern POBJECT_TYPE * IoDriverObjectType;

	typedef struct _KLDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		PVOID ExceptionTable;
		ULONG ExceptionTableSize;
		PVOID GpValue;
		PVOID NonPagedDebugInfo;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		// ...
	} KLDR_DATA_TABLE_ENTRY, * PKLDR_DATA_TABLE_ENTRY;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		// ...
	} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	typedef struct _PEB_LDR_DATA
	{
		unsigned int Length;
		int Initialized;
		void* SSHandle;
		LIST_ENTRY InLoadOrderLinks;
		LIST_ENTRY InMemoryOrderLinks;
		LIST_ENTRY InInitializationOrderLinks;
		// ...
	} PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _COMPLETION_ROUTINE_CONTEXT
	{
		PVOID Buffer;
		ULONG BufferLength;
		PVOID OriginalContext;
		PIO_COMPLETION_ROUTINE OriginalRoutine;
	} COMPLETION_ROUTINE_CONTEXT, * PCOMPLETION_ROUTINE_CONTEXT;

	typedef struct _PEB64
	{
		unsigned char InheritedAddressSpace;	// 0x0000 
		unsigned char ReadImageFileExecOptions;	// 0x0001 
		unsigned char BeingDebugged;			// 0x0002 
		unsigned char BitField;					// 0x0003 
		unsigned char pad_0x0004[0x4];			// 0x0004
		PVOID Mutant;							// 0x0008 
		PVOID ImageBaseAddress;					// 0x0010 
		PPEB_LDR_DATA Ldr;						// 0x0018
		// ...
	} PEB64, * PPEB64;

	typedef struct _PEB_LDR_DATA32
	{
		ULONG Length;
		UCHAR Initialized;
		ULONG SsHandle;
		LIST_ENTRY32 InLoadOrderModuleList;
		LIST_ENTRY32 InMemoryOrderModuleList;
		LIST_ENTRY32 InInitializationOrderModuleList;
	} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

	typedef struct _LDR_DATA_TABLE_ENTRY32
	{
		LIST_ENTRY32 InLoadOrderLinks;
		LIST_ENTRY32 InMemoryOrderLinks;
		LIST_ENTRY32 InInitializationOrderLinks;
		ULONG DllBase;
		ULONG EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING32 FullDllName;
		UNICODE_STRING32 BaseDllName;
		ULONG Flags;
		USHORT LoadCount;
		USHORT TlsIndex;
		LIST_ENTRY32 HashLinks;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

	typedef struct _PEB32
	{
		UCHAR InheritedAddressSpace;
		UCHAR ReadImageFileExecOptions;
		UCHAR BeingDebugged;
		UCHAR BitField;
		ULONG Mutant;
		ULONG ImageBaseAddress;
		ULONG Ldr;
		ULONG ProcessParameters;
		ULONG SubSystemData;
		ULONG ProcessHeap;
		ULONG FastPebLock;
		ULONG AtlThunkSListPtr;
		ULONG IFEOKey;
		ULONG CrossProcessFlags;
		ULONG UserSharedInfoPtr;
		ULONG SystemReserved;
		ULONG AtlThunkSListPtr32;
		ULONG ApiSetMap;
	} PEB32, * PPEB32;

	extern "C" POBJECT_TYPE * IoDriverObjectType;
	extern "C"
		NTSYSAPI
		NTSTATUS
		NTAPI
		ObReferenceObjectByName(
			_In_ PUNICODE_STRING ObjectName,
			_In_ ULONG Attributes,
			_In_opt_ PACCESS_STATE AccessState,
			_In_opt_ ACCESS_MASK DesiredAccess,
			_In_ POBJECT_TYPE ObjectType,
			_In_ KPROCESSOR_MODE AccessMode,
			_Inout_opt_ PVOID ParseContext,
			_Out_ PVOID * Object
		);

	typedef VOID
	(*MouseClassServiceCallback)(
		PDEVICE_OBJECT DeviceObject,
		PMOUSE_INPUT_DATA InputDataStart,
		PMOUSE_INPUT_DATA InputDataEnd,
		PULONG InputDataConsumed
		);

	typedef struct _MOUSE_OBJECT
	{
		PDEVICE_OBJECT mouse_device;
		MouseClassServiceCallback service_callback;
	} MOUSE_OBJECT, * PMOUSE_OBJECT;

	extern "C" NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation( ULONG, PVOID, ULONG, PULONG );
	extern "C" NTSYSAPI NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
	//extern "C" NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
	extern "C" NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(PUNICODE_STRING ObjectName, ULONG Attributes, PACCESS_STATE PassedAccessState, ACCESS_MASK DesiredAccess, POBJECT_TYPE ObjectType, KPROCESSOR_MODE AccessMode, PVOID ParseContext, PVOID* Object);
	extern "C" NTSYSAPI NTSTATUS NTAPI MmCopyVirtualMemory(PEPROCESS SourceProcess, PVOID SourceAddress, PEPROCESS TargetProcess, PVOID TargetAddress, SIZE_T BufferSize, KPROCESSOR_MODE PreviousMode, PSIZE_T ReturnSize);
	extern "C" NTSYSAPI PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
	extern "C" NTSYSAPI PPEB NTAPI PsGetProcessPeb(PEPROCESS Process);
	extern "C" NTSYSAPI PVOID NTAPI PsGetProcessWow64Process(PEPROCESS Process);

	extern "C" __declspec(dllimport)
		NTSTATUS NTAPI ZwProtectVirtualMemory(
			HANDLE ProcessHandle,
			PVOID * BaseAddress,
			PSIZE_T ProtectSize, //PULONG ProtectSize,
			ULONG NewProtect,
			PULONG OldProtect
		);

	extern "C" __declspec(dllimport)
		NTSTATUS NTAPI MmCopyVirtualMemory(
			PEPROCESS FromProcess,
			PVOID FromAddress,
			PEPROCESS ToProcess,
			PVOID ToAddress,
			SIZE_T BufferSize,
			KPROCESSOR_MODE PreviousMode,
			PSIZE_T NumberOfBytesCopied
		);

	NTSTATUS KeForceWriteMemory(
		_In_ PEPROCESS TargetProc,
		_In_ PVOID Address,
		_In_ PVOID Buffer,
		_In_ ULONG Size);

	image_data_t find_module( const char* module_name );
	NTSTATUS WriteProcessMemory(int process_id, void* address, void* buffer, size_t size, size_t size_copied);
	NTSTATUS ReadProcessMemory(int process_id, void* address, void* buffer, size_t size, size_t	size_copied);
	PVOID get_client_module(HANDLE pid);
	PVOID get_engine_module(HANDLE pid, LPCWSTR module_name);
	NTSTATUS init_mouse(PMOUSE_OBJECT mouse_obj);
	void call_mouse(MOUSE_OBJECT mouse_obj, long x, long y, unsigned short button_flags);
	NTSTATUS protect_virtual_memory(
		UINT_PTR	process_id,
		PVOID		address,
		ULONG		protection,
		ULONG		protection_old,
		SIZE_T		sizes);


}

#endif