#include <mmdeviceapi.h>
#include <Audioclient.h>

#include "uuids.h"

extern "C" {

uuids_t get_uuids()
{
	return {
		__uuidof(MMDeviceEnumerator),
		__uuidof(IMMDeviceEnumerator),
		__uuidof(IAudioClient),
		__uuidof(IAudioRenderClient),
	};
}
}
