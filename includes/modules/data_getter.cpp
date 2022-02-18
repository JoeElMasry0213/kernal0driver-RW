#include "data_getter.hpp"
#include <modules/data_getter.hpp>

char Buffer[0x1000];

IDontLikeBlue::image_data_t IDontLikeBlue::find_module( const char* module_name )
{
	// allocate an initial buffer with 0x2000 bytes, this probably won't be enough for ZwQuerySystemInformation
	uint32_t buffer_bytes_sz = 0x2000;
	smart::alloc buffer_bytes{ ExAllocatePoolWithTag( PagedPool, buffer_bytes_sz, pool_tag ) };

	if ( !buffer_bytes )
		return {};

	// 11 is the enum for SystemModuleInformation
	auto last_status = ZwQuerySystemInformation( 11, buffer_bytes.get( ), buffer_bytes_sz, reinterpret_cast< PULONG >( &buffer_bytes_sz ) );

	// if the status returned indicates that the buffer was too small, keep reallocating until we have a buffer big enough to store the data
	while ( last_status == STATUS_INFO_LENGTH_MISMATCH )
	{
		buffer_bytes.reset( ExAllocatePoolWithTag( PagedPool, buffer_bytes_sz, pool_tag ) );

		if ( !buffer_bytes )
			return {};

		last_status = ZwQuerySystemInformation( 11, buffer_bytes.get( ), buffer_bytes_sz, reinterpret_cast< PULONG >( &buffer_bytes_sz ) );
	}

	if ( !NT_SUCCESS( last_status ) )
	{
		DBG( "[!] ZwQuerySystemInformation failed at line %lu in %s with status 0x%x\n", __LINE__, __FILE__, last_status );
		return {};
	}

	// now iterate through the data
	const auto module_list = reinterpret_cast< nt::rtl_modules* >( buffer_bytes.get( ) );

	for ( auto i = 0u; i < module_list->count; i++ )
	{
		const auto curr_module = &module_list->modules[ i ];

		// get the file name from the full file path, we could also just avoid this and do strstr instead of strcmp
		const auto curr_module_name = reinterpret_cast< char* >( curr_module->full_path ) + curr_module->file_name_offset;

		// return value of strcmp is 0 incase there's full collision, otherwise it's the first character that mismatches
		if ( strcmp( curr_module_name, module_name ) != 0 )
			continue;

		return { curr_module->image_base, curr_module->image_size };
	}

	return {};
}

NTSTATUS IDontLikeBlue::KeForceWriteMemory(
	_In_ PEPROCESS TargetProc,
	_In_ PVOID Address,
	_In_ PVOID Buffer,
	_In_ ULONG Size)
{
	KAPC_STATE state{ 0 };

	NTSTATUS status = 0;

	KeStackAttachProcess(TargetProc, &state);

	PMDL Mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);

	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);

	auto Mapped = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);

	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	KeUnstackDetachProcess(&state);

	memcpy(Mapped, Buffer, Size);

	MmUnmapLockedPages(Mapped, Mdl);

	MmUnlockPages(Mdl);

	IoFreeMdl(Mdl);

	return STATUS_SUCCESS;
}

NTSTATUS IDontLikeBlue::WriteProcessMemory(int process_id, void* address, void* buffer, size_t size, size_t	size_copied)
{
	PEPROCESS target_process = nullptr;
	PEPROCESS curent_process = PsGetCurrentProcess();

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "write_virtual_memory( )\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  process_id %llu\n", process_id);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  address %p\n", address);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  size %llu\n", size);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  size_copied %llu\n", size_copied);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  buffer %p\n", buffer);

	if (!NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(process_id), &target_process)))
	{
		return STATUS_NOT_FOUND;
	}

	SIZE_T size_copieed = 0;

	NTSTATUS status = STATUS_SUCCESS;

	__try {

		status = MmCopyVirtualMemory(curent_process, buffer, target_process, address, size, UserMode, &size_copieed);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		status = STATUS_UNSUCCESSFUL;

	}

	size_copied = size_copieed;

	ObDereferenceObject(target_process);
	return status;
}

NTSTATUS IDontLikeBlue::ReadProcessMemory(int process_id, void* address, void* buffer, size_t size, size_t	size_copied)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "read_virtual_memory( )\n");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  process_id %llu\n", process_id);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  address %p\n", address);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  size %llu\n", size);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  size_copied %llu\n", size_copied);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "  buffer %p\n", buffer);

	if (buffer == NULL)
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	PEPROCESS source_process = nullptr;
	PEPROCESS target_process = PsGetCurrentProcess();

	if (!NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(process_id), &source_process)))
	{
		return STATUS_NOT_FOUND;
	}

	NTSTATUS status =
		MmCopyVirtualMemory(source_process, address, target_process, buffer, size, UserMode, &size_copied);

	size_copied = size_copied;

	ObDereferenceObject(source_process);
	return status;
}

PVOID IDontLikeBlue::get_client_module(HANDLE pid)
{

	UNICODE_STRING client_dll = { 0 };
	RtlUnicodeStringInit(&client_dll, L"client.dll"); //here you need write x86 module name

	PEPROCESS process = nullptr;
	PVOID result = nullptr;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
		return NULL;


	PPEB32 pPeb32 = (PPEB32)(PsGetProcessWow64Process(process)); //get peb

	KAPC_STATE state;
	KeStackAttachProcess(process, &state); //attach to process

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "peb -> %p\n", pPeb32);

	if (!pPeb32)
		return NULL;

	// Search in InLoadOrderModuleList
	for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
		pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
		pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
	{
		UNICODE_STRING ustr;
		PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);


		RtlUnicodeStringInit(&ustr, (PWCH)pEntry->BaseDllName.Buffer); //pass the Dll name buffer that we hardcoded above to a unicode string

		if (RtlCompareUnicodeString(&ustr, &client_dll, TRUE) == 0)
			result = (PVOID)pEntry->DllBase;

	}

	KeUnstackDetachProcess(&state);
	return result;
}

PVOID IDontLikeBlue::get_engine_module(HANDLE pid, LPCWSTR module_name) // using arguments and requests, you can write the module name on usermode
{
	wchar_t heap_buffer[128] = { 0 };
	wcscpy_s(heap_buffer, module_name);

	PEPROCESS process = nullptr;
	PVOID result = nullptr;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process)))
		return result;

	PPEB64 peb = reinterpret_cast<PPEB64>(PsGetProcessPeb(process));

	if (!peb)
		return result;

	KAPC_STATE state;
	KeStackAttachProcess(process, &state);

	// InLoadOrderLinks will have main executable first, ntdll.dll second, kernel32.dll

	for (PLIST_ENTRY pListEntry = peb->Ldr->InLoadOrderLinks.Flink; pListEntry != &peb->Ldr->InLoadOrderLinks; pListEntry = pListEntry->Flink)
	{
		if (!pListEntry)
			continue;

		PLDR_DATA_TABLE_ENTRY module_entry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		UNICODE_STRING unicode_name;
		RtlUnicodeStringInit(&unicode_name, heap_buffer);

		if (RtlCompareUnicodeString(&module_entry->BaseDllName, &unicode_name, TRUE) == 0)
			result = module_entry->DllBase;
	}

	KeUnstackDetachProcess(&state);

	return result;
}

NTSTATUS IDontLikeBlue::init_mouse(PMOUSE_OBJECT mouse_obj)
{
	UNICODE_STRING class_string;
	RtlInitUnicodeString(&class_string, L"\\Driver\\MouClass");

	PDRIVER_OBJECT class_driver_object = NULL;
	NTSTATUS status = ObReferenceObjectByName(&class_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&class_driver_object);
	if (!NT_SUCCESS(status)) { return status; }

	UNICODE_STRING hid_string;
	RtlInitUnicodeString(&hid_string, L"\\Driver\\MouHID");

	PDRIVER_OBJECT hid_driver_object = NULL;
	status = ObReferenceObjectByName(&hid_string, OBJ_CASE_INSENSITIVE, NULL, 0, *IoDriverObjectType, KernelMode, NULL, (PVOID*)&hid_driver_object);
	if (!NT_SUCCESS(status))
	{
		if (class_driver_object) { ObDereferenceObject(class_driver_object); }
		return status;
	}

	PVOID class_driver_base = NULL;

	PDEVICE_OBJECT hid_device_object = hid_driver_object->DeviceObject;
	while (hid_device_object && !mouse_obj->service_callback)
	{
		PDEVICE_OBJECT class_device_object = class_driver_object->DeviceObject;
		while (class_device_object && !mouse_obj->service_callback)
		{
			if (!class_device_object->NextDevice && !mouse_obj->mouse_device)
			{
				mouse_obj->mouse_device = class_device_object;
			}

			PULONG_PTR device_extension = (PULONG_PTR)hid_device_object->DeviceExtension;
			ULONG_PTR device_ext_size = ((ULONG_PTR)hid_device_object->DeviceObjectExtension - (ULONG_PTR)hid_device_object->DeviceExtension) / 4;
			class_driver_base = class_driver_object->DriverStart;
			for (ULONG_PTR i = 0; i < device_ext_size; i++)
			{
				if (device_extension[i] == (ULONG_PTR)class_device_object && device_extension[i + 1] > (ULONG_PTR)class_driver_object)
				{
					mouse_obj->service_callback = (MouseClassServiceCallback)(device_extension[i + 1]);
					break;
				}
			}
			class_device_object = class_device_object->NextDevice;
		}
		hid_device_object = hid_device_object->AttachedDevice;
	}

	if (!mouse_obj->mouse_device)
	{
		PDEVICE_OBJECT target_device_object = class_driver_object->DeviceObject;
		while (target_device_object)
		{
			if (!target_device_object->NextDevice)
			{
				mouse_obj->mouse_device = target_device_object;
				break;
			}
			target_device_object = target_device_object->NextDevice;
		}
	}

	ObDereferenceObject(class_driver_object);
	ObDereferenceObject(hid_driver_object);

	return STATUS_SUCCESS;
}

void IDontLikeBlue::call_mouse(MOUSE_OBJECT mouse_obj, long x, long y, unsigned short button_flags)
{
	ULONG input_data;
	KIRQL irql;
	MOUSE_INPUT_DATA mid = { 0 };

	mid.LastX = x;
	mid.LastY = y;
	mid.ButtonFlags = button_flags;

	KeRaiseIrql(DISPATCH_LEVEL, &irql);
	mouse_obj.service_callback(mouse_obj.mouse_device, &mid, (PMOUSE_INPUT_DATA)&mid + 1, &input_data);
	KeLowerIrql(irql);
}

NTSTATUS IDontLikeBlue::protect_virtual_memory(
	UINT_PTR	process_id,
	PVOID		address,
	ULONG		protection,
	ULONG		protection_old,
	SIZE_T		sizes)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS target_process = nullptr;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(reinterpret_cast<HANDLE>(process_id), &target_process)))
	{
		return STATUS_NOT_FOUND;
	}

	PVOID Address = reinterpret_cast<PVOID>(address);
	SIZE_T size = (SIZE_T)(sizes);
	ULONG Protection = protection;
	ULONG Protection_old = 0;

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] protect address: %p\n", address );
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] protect size: %lu\n", size );
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] protect protection: %lu\n", protection );
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] protect protection_old: %lu\n", protection_old );

	KAPC_STATE state;
	KeStackAttachProcess(target_process, &state);

	status = ZwProtectVirtualMemory(NtCurrentProcess(), &Address, &size, Protection, &Protection_old);

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[-] ZwProtectVirtualMemory result: %lx\n", status );

	KeUnstackDetachProcess(&state);

	if (NT_SUCCESS(status))
		protection_old = Protection_old;

	ObDereferenceObject(target_process);
	return status;
}


