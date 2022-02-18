#include "control.hpp"

IDontLikeBlue::MOUSE_OBJECT mouse_obj = { 0 };

NTSTATUS IDontLikeBlue::control_handler( PDEVICE_OBJECT, PIRP request_packet )
{
	const auto curr_stack = request_packet->Tail.Overlay.CurrentStackLocation;

	if ( !curr_stack )
		return STATUS_INVALID_PARAMETER;

	static const auto ValidateHwnd = reinterpret_cast<nt::tag_wnd * (*)(uint64_t)>(
		find_export("win32kbase.sys", "ValidateHwnd")
		);

	if (!ValidateHwnd)
	{
		DBG( "[!] Can't find ValidateHwnd export, catastrophic error\n" );
		return STATUS_UNSUCCESSFUL;
	}

	if (!mouse_obj.service_callback || !mouse_obj.mouse_device) { init_mouse(&mouse_obj); }

	SIZE_T bytes_operated = 0;
	NTSTATUS operation_status = STATUS_SUCCESS;
	
	switch ( curr_stack->Parameters.DeviceIoControl.IoControlCode )
	{
	case REQUEST_GET_WINDOW:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] GET Window called\n");

		const auto curr_request = reinterpret_cast<generic_thread_ctx_t*>(request_packet->AssociatedIrp.SystemBuffer);

		if (!curr_request)
		{
			DBG( "[!] Corrupt request sent to the dispatcher\n" );
			break;
		}

		const auto window_instance = ValidateHwnd(curr_request->window_handle);

		if (!window_instance
			|| !window_instance->thread_info)
		{
			DBG( "[!] ValidateHwnd call failed\n" );
			break;
		}

		curr_request->thread_pointer = reinterpret_cast<uint64_t>(window_instance->thread_info->owning_thread);

		//Printf("thread_pointer %p\n", curr_request->thread_pointer);
		//Printf("owning_thread %p\n", window_instance->thread_info->owning_thread);
		//Printf("window_instance %p\n", window_instance);
		//Printf("ValidateHwnd %p\n", ValidateHwnd);

		bytes_operated = sizeof(generic_thread_ctx_t);
		break;

		break;
	}
	case REQUEST_SET_WINDOW:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] SET Window called\n");

		const auto curr_request = reinterpret_cast<generic_thread_ctx_t*>(request_packet->AssociatedIrp.SystemBuffer);

		if (!curr_request)
		{
			DBG( "[!] Corrupt request sent to the dispatcher\n" );
			break;
		}

		const auto window_instance = ValidateHwnd(curr_request->window_handle);

		if (!window_instance
			|| !window_instance->thread_info)
		{
			DBG( "[!] ValidateHwnd call failed\n" );
			break;
		}

		window_instance->thread_info->owning_thread = reinterpret_cast<PETHREAD>(curr_request->thread_pointer);

		//Printf("thread_pointer2 %p\n", curr_request->thread_pointer);
		//Printf("owning_thread 2 %p\n", window_instance->thread_info->owning_thread);
		//Printf("window_instance 2 %p\n", window_instance);
		//Printf("ValidateHwnd 2 %p\n", ValidateHwnd);

		bytes_operated = sizeof(generic_thread_ctx_t);
		break;

		break;
	}
	case REQUEST_READ:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Read called\n");

		const auto request = reinterpret_cast<memory_structs*>(request_packet->AssociatedIrp.SystemBuffer);

		if (!request)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Corrupt request sent to the commer\n");
			break;
		}


		IDontLikeBlue::ReadProcessMemory(request->ProcessID, request->Address, request->value, request->size, request->size_copied);

		bytes_operated = sizeof(memory_structs);
		break;
	}
	case REQUEST_WRITE:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Write called\n");

		const auto request = reinterpret_cast<memory_structs*>(request_packet->AssociatedIrp.SystemBuffer);

		if (!request)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Corrupt request sent to the commer\n");
			break;
		}

		IDontLikeBlue::WriteProcessMemory(request->ProcessID, request->Address, request->value, request->size, request->size_copied);

		bytes_operated = sizeof(memory_structs);
		break;
	}
	case REQUEST_BASE:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Base called\n");

		PEPROCESS pe;
		const auto request = reinterpret_cast<memory_structs*>(request_packet->AssociatedIrp.SystemBuffer);

		if (!request)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Corrupt request sent to the commer\n");
			break;
		}

		PsLookupProcessByProcessId((HANDLE)request->ProcessID, &pe);
		request->data = IDontLikeBlue::PsGetProcessSectionBaseAddress(pe);
		ObfDereferenceObject(pe);

		bytes_operated = sizeof(memory_structs);
		break;
	}
	case REQUEST_CLIENT_MODULE:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Client called\n");

		const auto request = reinterpret_cast<memory_structs*>(request_packet->AssociatedIrp.SystemBuffer);

		if (!request)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Corrupt request sent to the commer\n");
			break;
		}

		request->data = IDontLikeBlue::get_client_module((HANDLE)request->ProcessID); //csgo module hardcoded

		bytes_operated = sizeof(memory_structs);
		break;
	}
	case REQUEST_ENGINE_MODULE:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Engine called\n");

		const auto request = reinterpret_cast<memory_structs*>(request_packet->AssociatedIrp.SystemBuffer);

		if (!request)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Corrupt request sent to the commer\n");
			break;
		}

		request->data = IDontLikeBlue::get_engine_module((HANDLE)request->ProcessID, request->modulename); //csgo module hardcoded

		bytes_operated = sizeof(memory_structs);
		break;
	}
	case REQUEST_MOUSE_GAMER:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Mouse Gamer called\n");

		const auto request = reinterpret_cast<mouse_gamer*>(request_packet->AssociatedIrp.SystemBuffer);

		if (!request)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Corrupt request sent to the commer\n");
			break;
		}

		IDontLikeBlue::call_mouse(mouse_obj, request->pitch, request->yaw, request->button_flags);

		bytes_operated = sizeof(mouse_gamer);
		break;
	}
	case REQUEST_PROTECTION:
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Protection called\n");

		const auto request = reinterpret_cast<protection_struct*>(request_packet->AssociatedIrp.SystemBuffer);

		if (!request)
		{
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[!] Corrupt request sent to the commer\n");
			break;
		}

		request->result = IDontLikeBlue::protect_virtual_memory(request->process_id, request->address, request->protection, request->protection_old, request->size);

		bytes_operated = sizeof(protection_struct);
		break;
	}
	default:break;
	}

	request_packet->IoStatus.Information = static_cast< uint32_t >( bytes_operated );
	request_packet->IoStatus.Status = operation_status;

	IoCompleteRequest( request_packet, FALSE );

	return operation_status;
}
