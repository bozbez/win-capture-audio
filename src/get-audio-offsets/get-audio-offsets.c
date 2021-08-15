#include <vadefs.h>
#include <windows.h>
#include <psapi.h>

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <inttypes.h>

#include <Audioclient.h>
#include <mmdeviceapi.h>

#include "uuids.h"

#define REFTIMES_PER_SEC 10000000
#define REFTIMES_PER_MILLISEC 10000

#define SAFE_RELEASE(punk)                     \
	if ((punk) != NULL) {                  \
		(punk)->lpVtbl->Release(punk); \
		(punk) = NULL;                 \
	}

typedef struct wasapi_info {
	IAudioClient *client;
	IAudioRenderClient *render_client;

	WAVEFORMATEX *format;
} wasapi_info_t;

static inline HRESULT wasapi_info_init(wasapi_info_t *info)
{
	HRESULT hr = E_FAIL;

	uuids_t uuids = get_uuids();

	REFERENCE_TIME requested_duration = REFTIMES_PER_SEC;
	REFERENCE_TIME actual_duration;

	IMMDeviceEnumerator *enumerator = NULL;
	hr = CoCreateInstance(&uuids.CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL,
			      &uuids.IID_IMMDeviceEnumerator,
			      (void **)&enumerator);

	if (FAILED(hr)) {
		printf("failed to create device enumerator\n");
		goto exit;
	}

	IMMDevice *device = NULL;
	hr = enumerator->lpVtbl->GetDefaultAudioEndpoint(enumerator, eRender,
							 eConsole, &device);

	if (FAILED(hr)) {
		printf("failed get default endpoint\n");
		goto exit;
	}

	hr = device->lpVtbl->Activate(device, &uuids.IID_IAudioClient,
				      CLSCTX_ALL, NULL, (void **)&info->client);

	if (FAILED(hr)) {
		printf("failed to get client\n");
		goto exit;
	}

	hr = info->client->lpVtbl->GetMixFormat(info->client, &info->format);

	if (FAILED(hr)) {
		printf("failed to get mix format\n");
		goto exit;
	}

	hr = info->client->lpVtbl->Initialize(info->client,
					      AUDCLNT_SHAREMODE_SHARED, 0,
					      requested_duration, 0,
					      info->format, NULL);

	if (FAILED(hr)) {
		printf("failed to initialize client\n");
		goto exit;
	}

	hr = info->client->lpVtbl->GetService(info->client,
					      &uuids.IID_IAudioRenderClient,
					      (void **)&info->render_client);

	if (FAILED(hr)) {
		printf("failed to get render client\n");
		goto exit;
	}

exit:

	SAFE_RELEASE(enumerator);
	SAFE_RELEASE(device);

	return hr;
}

static inline void wasapi_info_destroy(wasapi_info_t *info)
{
	CoTaskMemFree(info->format);

	SAFE_RELEASE(info->render_client);
	SAFE_RELEASE(info->client);
}

static MODULEINFO get_module_info(HMODULE module)
{
	MODULEINFO info;
	GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info));

	return info;
}

static bool is_ptr_in_module(HMODULE module, uintptr_t func)
{
	MODULEINFO info = get_module_info(module);

	return (func > (uintptr_t)info.lpBaseOfDll) &&
	       (func < (uintptr_t)info.lpBaseOfDll + info.SizeOfImage);
}

static inline uint32_t vtable_offset(HMODULE module, void *cls,
				     unsigned int offset)
{
	uintptr_t *vtable = *(uintptr_t **)cls;
	return (uint32_t)(vtable[offset] - (uintptr_t)module);
}

static uint32_t scan_render_client_client_offset(wasapi_info_t *info)
{
	char *client_candidate = (char *)info->render_client;
	for (int i = 1; i < 32 * 8; ++i) {
		IAudioClient **client_ptr =
			(IAudioClient **)&client_candidate[i];

		if (*client_ptr == info->client)
			return i;
	}

	return 0;
}

static bool wave_formats_equal(WAVEFORMATEX *w1, WAVEFORMATEX *w2)
{
	__try {
		int neq = memcmp(w1, w2, sizeof(WAVEFORMATEX));
		return !neq;
	} __except (EXCEPTION_EXECUTE_HANDLER) {
	}

	return false;
}

static uint32_t scan_render_client_format_offset(wasapi_info_t *info)
{
	char *format_candidate = (char *)info->render_client;
	for (int i = 1; i < 32 * 8; ++i) {
		WAVEFORMATEX **format_ptr =
			(WAVEFORMATEX **)&format_candidate[i];

		if (wave_formats_equal(*format_ptr, info->format))
			return i;
	}

	printf("Format pointer not found\n");
	return 0;
}

int main()
{
	int ret = 1;

	if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED))) {
		printf("failed to initialize COM library");
		return ret;
	};

	wasapi_info_t info;
	HRESULT hr = wasapi_info_init(&info);

	if (FAILED(hr)) {
		printf("wasapi init failed: %ld\n", hr);
		goto exit;
	}

	uintptr_t client_vtbl = (uintptr_t)info.client->lpVtbl;
	uintptr_t render_client_vtbl = (uintptr_t)info.render_client->lpVtbl;

	uint32_t render_client_client_offset =
		scan_render_client_client_offset(&info);

	uint32_t render_client_format_offset =
		scan_render_client_format_offset(&info);

	HMODULE module = GetModuleHandleW(L"audioses.dll");
	if (module == NULL) {
		printf("failed to find loaded audioses.dll\n");
		goto exit;
	}

	uintptr_t module_addr = (uintptr_t)get_module_info(module).lpBaseOfDll;

	if (!is_ptr_in_module(module, client_vtbl)) {
		printf("client vtbl not in found audioses.dll!\n");
		goto exit;
	}

	if (!is_ptr_in_module(module, render_client_vtbl)) {
		printf("render client vtbl not in found audioses.dll!\n");
		goto exit;
	}

	printf("[wasapi]\n");
	printf("client_vtbl=0x%x\n", (uint32_t)(client_vtbl - module_addr));
	printf("render_client_vtbl=0x%x\n",
	       (uint32_t)(render_client_vtbl - module_addr));
	printf("m_render_client_client=0x%x\n", render_client_client_offset);
	printf("m_render_client_format=0x%x\n", render_client_format_offset);

	ret = 0;

exit:
	wasapi_info_destroy(&info);
	return ret;
}