#ifndef WNDHIJACK_CONTROL_MJ_HPP
#define WNDHIJACK_CONTROL_MJ_HPP

#include <modules/export_getter.hpp>
#include <defs/drv.hpp>
#include <defs/nt.hpp>

//communication YOU REALLY NEED CHANGE IT IF YOUR DRIVER GETS BLACKLISTED
#define REQUEST_WRITE      CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7432, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define REQUEST_READ       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7433, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define REQUEST_BASE       CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7434, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define REQUEST_GET_WINDOW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7435, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define REQUEST_SET_WINDOW CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7436, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define REQUEST_CLIENT_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7437, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define REQUEST_ENGINE_MODULE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7438, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define REQUEST_MOUSE_GAMER CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7439, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define REQUEST_PROTECTION CTL_CODE(FILE_DEVICE_UNKNOWN, 0x7431, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

namespace IDontLikeBlue
{
	struct generic_thread_ctx_t
	{
		uint64_t window_handle;
		uint64_t thread_pointer;
	};

	struct memory_structs 
	{
		int ProcessID = 0;
		void* Address;
		void* value;
		SIZE_T size;
		void* data;
		LONG module32;
		const wchar_t* modulename;
		void* bufferAddress;
		SIZE_T size_copied;
	};

	struct mouse_gamer
	{
		long pitch;
		long yaw;
		unsigned short button_flags;
	};

	struct protection_struct
	{
		UINT_PTR	process_id;
		PVOID		address;
		SIZE_T		size;
		ULONG		protection;
		ULONG		protection_old;
		ULONG       result;
	};

	NTSTATUS control_handler( PDEVICE_OBJECT device_object, PIRP request_packet );
}

#endif