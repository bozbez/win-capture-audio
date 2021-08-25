#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct audio_uuids {
	CLSID CLSID_MMDeviceEnumerator;
	IID IID_IMMDeviceEnumerator;

	IID IID_IAudioClient;
	IID IID_IAudioCaptureClient;

	IID IID_IAudioSessionControl;
	IID IID_IAudioSessionControl2;

} audio_uuids_t;

audio_uuids_t get_uuids();

#ifdef __cplusplus
}
#endif