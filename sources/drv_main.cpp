#define _NO_CRT_STDIO_INLINE
#include <utils/drv_utils.hpp>

#include <comm/filler.hpp>
#include <comm/control.hpp>

#include <defs/hide_driver.h>
#include <defs/version.h>

using namespace IDontLikeBlue;

VOID Printf(_In_ PCCH Format, ...)
{
    CHAR Message[512];
    va_list VaList;
    __crt_va_start(VaList, Format);
    const ULONG N = _vsnprintf_s(Message, sizeof(Message) - 1, Format, VaList);
    Message[N] = L'\0';
    vDbgPrintExWithPrefix("[IOCTL SERVER] ", DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, Message, VaList);
    __crt_va_end(VaList);
}

VOID DestroyDriverInformation(IN PKLDR_DATA_TABLE_ENTRY DriverSection) {
	DriverSection->BaseDllName.Buffer[0] = L'\0';
	DriverSection->BaseDllName.Length = 0;
	DriverSection->BaseDllName.MaximumLength = 0;
}

void DriverUnload( PDRIVER_OBJECT driver_object )
{
	auto dos_device_ustr = USTR( IDontLikeBlue::dos_device_name );

	IoDeleteSymbolicLink( &dos_device_ustr );
	IoDeleteDevice( driver_object->DeviceObject );
}

NTSTATUS DriverDelete(PUNICODE_STRING pUsDriverPath)
{
    IO_STATUS_BLOCK IoStatusBlock;
    HANDLE FileHandle;
    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(
        &ObjectAttributes,
        pUsDriverPath,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        0,
        0);

    NTSTATUS Status = IoCreateFileEx(&FileHandle,
        SYNCHRONIZE | DELETE,
        &ObjectAttributes,
        &IoStatusBlock,
        nullptr,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr,
        0,
        CreateFileTypeNone,
        nullptr,
        IO_NO_PARAMETER_CHECKING,
        nullptr);

    if (!NT_SUCCESS(Status))
    {
        return Status;
    }

    PFILE_OBJECT FileObject;
    Status = ObReferenceObjectByHandleWithTag(FileHandle,
        SYNCHRONIZE | DELETE,
        *IoFileObjectType,
        KernelMode,
        'aniF',
        reinterpret_cast<PVOID*>(&FileObject),
        nullptr);
    if (!NT_SUCCESS(Status))
    {
        ObCloseHandle(FileHandle, KernelMode);
        return Status;
    }

    const PSECTION_OBJECT_POINTERS SectionObjectPointer = FileObject->SectionObjectPointer;
    SectionObjectPointer->ImageSectionObject = nullptr;

    // call MmFlushImageSection, make think no backing image and let NTFS to release file lock
    CONST BOOLEAN ImageSectionFlushed = MmFlushImageSection(SectionObjectPointer, MmFlushForDelete);

    ObfDereferenceObject(FileObject);
    ObCloseHandle(FileHandle, KernelMode);

    if (ImageSectionFlushed)
    {
        // Delete's the Driver
        Status = ZwDeleteFile(&ObjectAttributes);
        if (NT_SUCCESS(Status))
        {
            return Status;
        }
    }
    return Status;
}

MiProcessLoaderEntry GetMiProcessLoaderEntry()
{
    MiProcessLoaderEntry m_MiProcessLoaderEntry = NULL;
    ULONG win_ver = get_w_ver();

    Printf("[!] Win Version: %d\n", win_ver);

    if (win_ver == 1803 || win_ver == 1809 || win_ver == 1903 || win_ver == 1909)
    {
        m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_10();
        return m_MiProcessLoaderEntry;
    }

    else if (win_ver == 2004)
    {
        m_MiProcessLoaderEntry = Get_MiProcessLoaderEntry_WIN_10_2004();
        return m_MiProcessLoaderEntry;
    }

    return m_MiProcessLoaderEntry;
}

NTSTATUS DriverEntry( PDRIVER_OBJECT driver_object, PUNICODE_STRING )
{
	Printf( "[+] entry point called\n" );

    {// this is a cleaner
        MiProcessLoaderEntry m_MiProcessLoaderEntry = NULL;
        m_MiProcessLoaderEntry = GetMiProcessLoaderEntry(); //works on 1809/1909 - 2004
        m_MiProcessLoaderEntry(driver_object->DriverSection, 0);
    }// honestly i preffer this cleaner, the cleaner above can cause BSOD some times, but is more fast than this ^^


    ////{ //this is another cleaner, you should use one.
    ////    PLDR_DATA_TABLE_ENTRY CurDriverEntry = (PLDR_DATA_TABLE_ENTRY)driver_object->DriverSection;
    ////    PLDR_DATA_TABLE_ENTRY NextDriverEntry = (PLDR_DATA_TABLE_ENTRY)CurDriverEntry->InLoadOrderLinks.Flink;
    ////    PLDR_DATA_TABLE_ENTRY PrevDriverEntry = (PLDR_DATA_TABLE_ENTRY)CurDriverEntry->InLoadOrderLinks.Blink;

    ////    PrevDriverEntry->InLoadOrderLinks.Flink = CurDriverEntry->InLoadOrderLinks.Flink;
    ////    NextDriverEntry->InLoadOrderLinks.Blink = CurDriverEntry->InLoadOrderLinks.Blink;

    ////    CurDriverEntry->InLoadOrderLinks.Flink = (PLIST_ENTRY)CurDriverEntry;
    ////    CurDriverEntry->InLoadOrderLinks.Blink = (PLIST_ENTRY)CurDriverEntry;
    ////    DestroyDriverInformation((PKLDR_DATA_TABLE_ENTRY)driver_object->DriverSection);
    ////}

	Printf("[+] Table Cleaned\n");

	auto dos_device_ustr = USTR( IDontLikeBlue::dos_device_name );//driver name, you need change it if your driver gets blacklisted
	auto device_ustr = USTR( IDontLikeBlue::device_name );//driver name, you need change it if your driver gets blacklisted

	if ( !NT_SUCCESS( IoCreateDevice( driver_object,
		 0,
		 &device_ustr,
		 FILE_DEVICE_UNKNOWN,
		 FILE_DEVICE_SECURE_OPEN,
		 FALSE,
		 &IDontLikeBlue::device_object ) ) )
	{
		Printf( "[!] failed to create device object\n" );
		return STATUS_UNSUCCESSFUL;
	}

	if ( !NT_SUCCESS( IoCreateSymbolicLink( &dos_device_ustr,
		 &device_ustr ) ) )
	{
        Printf( "[!] failed to create symbolic link\n" );
		return STATUS_UNSUCCESSFUL;
	}

	for ( auto i = 0u; i < IRP_MJ_MAXIMUM_FUNCTION; i++ )
		driver_object->MajorFunction[ i ] = IDontLikeBlue::filler_handler;

	driver_object->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = IDontLikeBlue::control_handler;
	driver_object->DriverUnload = DriverUnload;

	IDontLikeBlue::device_object->Flags |= DO_DIRECT_IO;
	IDontLikeBlue::device_object->Flags &= ~DO_DEVICE_INITIALIZING;

    PUNICODE_STRING pusDriverPath = NULL;
    pusDriverPath = &((PKLDR_DATA_TABLE_ENTRY)driver_object->DriverSection)->FullDllName;
    DriverDelete(pusDriverPath);

    Printf( "[!] initialized driver!\n" );

	return STATUS_SUCCESS;
}