#ifndef WNDHIJACK_DRIVER_DEFS_HPP
#define WNDHIJACK_DRIVER_DEFS_HPP

#include <ntifs.h>
#include <stdint.h>

namespace IDontLikeBlue
{
	struct image_data_t
	{
		uint64_t base_address;
		uint32_t image_size;
	};

	constexpr uint32_t pool_tag = static_cast< uint32_t >( 's9lo' );//same for it

	constexpr const wchar_t* device_name = L"\\Device\\DINHEIROS"; //driver name, you need change it if your driver gets blacklisted
	constexpr const wchar_t* dos_device_name = L"\\DosDevices\\DINHEIROS"; //driver name, you need change it if your driver gets blacklisted
	//you will need change communications too at control.hpp
	 
	inline PDRIVER_OBJECT driver_object = nullptr;
	inline PDEVICE_OBJECT device_object = nullptr;
}

#define DBG(s, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,s,##__VA_ARGS__)

#endif