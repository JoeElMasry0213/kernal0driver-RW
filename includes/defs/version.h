
#pragma once
#include <ntifs.h>

ULONG get_w_ver()
{
	PWSTR value_name = static_cast<PWSTR>(ExAllocatePoolWithTag(PagedPool, 8 + sizeof(WCHAR), '8CcS'));

	if (!value_name)
		return 0;

	UNICODE_STRING registry_result;
	WCHAR registry_result_buffer[10] = { 0 };

	registry_result.Buffer = registry_result_buffer;
	registry_result.MaximumLength = sizeof(registry_result_buffer);
	registry_result.Length = 0;

	RTL_QUERY_REGISTRY_TABLE query_table[2] = { 0 };

	query_table[0].Flags = RTL_QUERY_REGISTRY_REQUIRED | RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_TYPECHECK;
	query_table[0].Name = L"ReleaseId";
	query_table[0].EntryContext = &registry_result;
	query_table->DefaultType = (REG_SZ << RTL_QUERY_REGISTRY_TYPECHECK_SHIFT) | REG_NONE;

	NTSTATUS status = RtlQueryRegistryValues(RTL_REGISTRY_ABSOLUTE, L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", query_table, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(value_name, '8CcS');
		return 0;
	}

	ULONG windows_version;
	RtlUnicodeStringToInteger(&registry_result, 10, &windows_version);

	ExFreePoolWithTag(value_name, '8CcS');
	return windows_version;

}
