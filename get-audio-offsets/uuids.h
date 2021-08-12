#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct uuids {
	CLSID CLSID_MMDeviceEnumerator;
	IID IID_IMMDeviceEnumerator;
	IID IID_IAudioClient;
	IID IID_IAudioRenderClient;
} uuids_t;

uuids_t get_uuids();

#ifdef __cplusplus
}
#endif