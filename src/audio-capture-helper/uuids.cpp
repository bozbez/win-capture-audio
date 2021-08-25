#include <mmdeviceapi.h>
#include <audioclient.h>
#include <audiopolicy.h>

#include "uuids.h"

extern "C" {

audio_uuids get_uuids()
{
	audio_uuids uuids;

	uuids.CLSID_MMDeviceEnumerator = __uuidof(MMDeviceEnumerator);
	uuids.IID_IMMDeviceEnumerator = __uuidof(IMMDeviceEnumerator);

	uuids.IID_IAudioClient = __uuidof(IAudioClient);
	uuids.IID_IAudioCaptureClient = __uuidof(IAudioCaptureClient);

	uuids.IID_IAudioSessionControl = __uuidof(IAudioSessionControl);
	uuids.IID_IAudioSessionControl2 = __uuidof(IAudioSessionControl2);

	return uuids;
}
}
