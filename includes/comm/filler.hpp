#ifndef WNDHIJACK_FILLER_MJ_HPP
#define WNDHIJACK_FILLER_MJ_HPP

#include <defs/drv.hpp>

namespace IDontLikeBlue
{
	inline NTSTATUS filler_handler( PDEVICE_OBJECT, PIRP )
	{
		return STATUS_SUCCESS;
	}
}

#endif