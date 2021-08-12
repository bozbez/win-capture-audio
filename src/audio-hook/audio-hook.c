#include <stdint.h>
#include <wchar.h>
#include <windows.h>
#include <stdbool.h>
#include <stdio.h>
#include <Audioclient.h>

#include <detours.h>

#include "../obfuscate.h"
#include "../hook-info.h"

#define UNUSED_PARAMETER(param) (void)param

#define DEBUG_OUTPUT

#ifdef DEBUG_OUTPUT
#define log(fmt, ...)                                                       \
	dbg_log("[OBS (%s:%d %s)] " fmt "\n", __FILE__, __LINE__, __func__, \
		##__VA_ARGS__)
#else
#define log(fmt, ...)
#endif

static audio_hook_offsets_t offsets;

static HANDLE hook_data_map;
static volatile audio_hook_data_t *hook_data;

static BYTE *data;

static uintptr_t audioses_module;

static IAudioClientVtbl *client_vtbl;
static IAudioRenderClientVtbl *render_client_vtbl;

static HANDLE capture_thread;

static HANDLE events[NUM_HOOK_EVENTS_TOTAL];

static bool hooked = false;

static void dbg_log(const char *fmt, ...)
{
	va_list argp;
	va_start(argp, fmt);

	char buf[256];
	vsprintf_s(buf, 256, fmt, argp);

	OutputDebugStringA(buf);
}

static bool init_offsets()
{
	HANDLE hook_metadata_map = NULL;
	volatile audio_hook_metadata_t *hook_metadata = NULL;

	log("opening metadata map: %ls", HOOK_METADATA_NAME);
	hook_metadata_map =
		OpenFileMappingW(FILE_MAP_READ, FALSE, HOOK_METADATA_NAME);

	if (!hook_metadata_map) {
		log("failed to open file mapping");
		return false;
	}

	hook_metadata = MapViewOfFile(hook_metadata_map, FILE_MAP_READ, 0, 0,
				      sizeof(audio_hook_metadata_t));

	if (!hook_metadata) {
		log("failed to open file map view");

		CloseHandle(hook_metadata_map);
		return false;
	}

	int ret = false;

	if (!hook_metadata->initialized) {
		log("hook metadata not (yet) initialized");
		goto exit;
	}

#ifdef _WIN64
	log("using 64-bit offsets");
	offsets = hook_metadata->offsets64;
#else
	log("using 32-bit offsets");
	offsets = hook_metadata->offsets32;
#endif

	log("loaded offsets: client_vtbl = 0x%x, "
	    "render_client_vtbl = 0x%x, m_render_client_format = 0x%x",
	    offsets.wasapi.client_vtbl, offsets.wasapi.render_client_vtbl,
	    offsets.wasapi.m_render_client_format);

	ret = true;

exit:
	UnmapViewOfFile((void *)hook_metadata);
	CloseHandle(hook_metadata_map);

	return ret;
}

static bool init_data()
{
	wchar_t name[MAX_PATH];
	format_name(name, HOOK_DATA_NAME);

	log("opening data map: %ls", name);
	hook_data_map = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
	if (!hook_data_map) {
		log("failed to open file mapping");
		return false;
	}

	hook_data = MapViewOfFile(hook_data_map, FILE_MAP_ALL_ACCESS, 0, 0,
				  sizeof(audio_hook_data_t));

	if (!hook_data) {
		log("failed to open file map view");

		CloseHandle(hook_data_map);
		return false;
	}

	return true;
}

static void destroy_data()
{
	if (hook_data != NULL) {
		UnmapViewOfFile((void *)hook_data);
		hook_data = NULL;
	}

	if (hook_data_map != NULL) {
		CloseHandle(hook_data_map);
		hook_data_map = NULL;
	}
}

static bool init_events()
{

	for (int i = HOOK_WO_EVENTS_START; i < HOOK_EVENTS_END; ++i) {
		wchar_t name[MAX_PATH];
		format_name(name, event_info[i].name);

		log("opening event: %ls", name);
		events[i] = OpenEventW(SYNCHRONIZE | EVENT_MODIFY_STATE, false,
				       name);

		if (events[i] == NULL) {
			log("failed to open event");
			return false;
		}
	}

	return true;
}

static void destroy_events()
{
	for (int i = HOOK_WO_EVENTS_START; i < HOOK_EVENTS_END; ++i) {
		if (events[i] != NULL) {
			CloseHandle(events[i]);
			events[i] = NULL;
		}
	}
}

static inline uint64_t get_clockfreq(void)
{
	static bool have_clockfreq = false;
	static LARGE_INTEGER clock_freq;

	if (!have_clockfreq) {
		QueryPerformanceFrequency(&clock_freq);
		have_clockfreq = true;
	}

	return clock_freq.QuadPart;
}

static inline uint64_t get_timestamp(void)
{
	LARGE_INTEGER current_time;
	double time_val;

	QueryPerformanceCounter(&current_time);
	time_val = (double)current_time.QuadPart;
	time_val *= 1000000000.0;
	time_val /= (double)get_clockfreq();

	return (uint64_t)time_val;
}

static inline uint64_t util_mul_div64(uint64_t num, uint64_t mul, uint64_t div)
{
	const uint64_t rem = num % div;

	return (num / div) * mul + (rem * mul) / div;
}

WAVEFORMATEXTENSIBLE *
format_from_render_client(IAudioRenderClient *render_client)
{
	uint32_t offset = offsets.wasapi.m_render_client_format;
	return *(WAVEFORMATEXTENSIBLE **)((uintptr_t)render_client + offset);
}

IAudioClient *client_from_render_client(IAudioRenderClient *render_client)
{
	uint32_t offset = offsets.wasapi.m_render_client_client;
	return *(IAudioClient **)((uintptr_t)render_client + offset);
}

HRESULT(STDMETHODCALLTYPE *RealReleaseBuffer)
(IAudioRenderClient *, UINT32, DWORD) = NULL;

HRESULT(STDMETHODCALLTYPE *RealGetBuffer)
(IAudioRenderClient *, UINT32, BYTE **) = NULL;

HRESULT STDMETHODCALLTYPE MyGetBuffer(IAudioRenderClient *This,
				      UINT32 NumFramesRequested, BYTE **ppData)
{
	HRESULT hr = RealGetBuffer(This, NumFramesRequested, ppData);
	data = hr == S_OK ? *ppData : NULL;

	return hr;
}

HRESULT STDMETHODCALLTYPE MyReleaseBuffer(IAudioRenderClient *This,
					  UINT32 NumFramesWritten,
					  DWORD dwFlags)
{
	if (data == NULL || NumFramesWritten == 0)
		goto exit;

	if (InterlockedCompareExchange(&hook_data->lock, 1, 0) != 0)
		goto exit;

	__try {
		WAVEFORMATEXTENSIBLE *format = format_from_render_client(This);
		if (format->Format.cbSize >= 22)
			hook_data->format = *format;
		else
			hook_data->format.Format = format->Format;

	} __except (EXCEPTION_EXECUTE_HANDLER) {
		log("failed to get buffer format");

		InterlockedExchange(&hook_data->lock, 0);
		goto exit;
	}

	size_t size = (hook_data->format.Format.wBitsPerSample / CHAR_BIT) *
		      hook_data->format.Format.nChannels * NumFramesWritten;

	if (size > HOOK_DATA_SIZE) {
		InterlockedExchange(&hook_data->lock, 0);
		goto exit;
	}

	memcpy((void *)hook_data->data, data, size);

	hook_data->timestamp = get_timestamp();
	hook_data->timestamp -=
		util_mul_div64(NumFramesWritten, 1000000000ULL,
			       hook_data->format.Format.nSamplesPerSec);

	hook_data->frames = NumFramesWritten;

	InterlockedExchange(&hook_data->lock, 0);
	SetEvent(events[HOOK_EVENT_DATA]);

exit:
	return RealReleaseBuffer(This, NumFramesWritten, dwFlags);
}

static void start_capture()
{
	log("starting capture");

	if (hooked) {
		log("already hooked, skipping");
		return;
	}

	if (!init_offsets()) {
		log("couldn't init offsets from hook metadata");
		return;
	}

	audioses_module = (uintptr_t)GetModuleHandleW(L"audioses.dll");
	if (audioses_module == (uintptr_t)NULL) {
		log("couldn't find loaded audioses.dll");
		return;
	}

	render_client_vtbl =
		(IAudioRenderClientVtbl *)(audioses_module +
					   offsets.wasapi.render_client_vtbl);
	client_vtbl = (IAudioClientVtbl *)(audioses_module +
					   offsets.wasapi.client_vtbl);

	log("audioses_module: %p, render_client_vtbl: %p, client_vtbl: %p",
	    (LPVOID)audioses_module, render_client_vtbl, client_vtbl);

	RealGetBuffer = render_client_vtbl->GetBuffer;
	RealReleaseBuffer = render_client_vtbl->ReleaseBuffer;

	data = NULL;

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourAttach((void **)&RealGetBuffer, MyGetBuffer);
	DetourAttach((void **)&RealReleaseBuffer, MyReleaseBuffer);

	LONG err = DetourTransactionCommit();

	if (err == NO_ERROR) {
		log("hooked successfully");

		hooked = true;
		SetEvent(events[HOOK_EVENT_ACTIVE]);
	} else {
		log("error while hooking: %ld", err);
	}
}

static void stop_capture()
{
	log("stopping capture");

	if (!hooked) {
		log("not hooked, skipping");
		return;
	}

	DetourTransactionBegin();
	DetourUpdateThread(GetCurrentThread());

	DetourDetach((void **)&RealGetBuffer, MyGetBuffer);
	DetourDetach((void **)&RealReleaseBuffer, MyReleaseBuffer);

	LONG err = DetourTransactionCommit();

	data = NULL;

	if (err == NO_ERROR) {
		log("unhooked successfully");
		hooked = false;
	} else {
		log("error while unhooking: %d", err);
	}
}

static DWORD WINAPI main_capture_thread(LPVOID lpParam)
{
	UNUSED_PARAMETER(lpParam);

	if (!init_data()) {
		log("failed to init data");
		goto exit;
	}

	if (!init_events()) {
		log("failed to init events");
		goto exit;
	}

	bool shutdown = false;
	while (!shutdown) {
		DWORD event_id = WaitForMultipleObjects(
			NUM_HOOK_WO_EVENTS, &events[HOOK_WO_EVENTS_START],
			FALSE, INFINITE);

		if (!(event_id >= WAIT_OBJECT_0 &&
		      event_id < WAIT_OBJECT_0 + NUM_HOOK_EVENTS_TOTAL)) {
			log("unexpected event id");
			break;
		}

		event_id -= WAIT_OBJECT_0;

		switch (event_id) {
		case HOOK_WO_EVENT_PING:
			log("pinged");
			SetEvent(events[HOOK_EVENT_READY]);
			break;
		case HOOK_WO_EVENT_START:
			start_capture();
			break;
		case HOOK_WO_EVENT_STOP:
			stop_capture();
			break;
		case HOOK_WO_EVENT_SHUTDOWN:
			stop_capture();
			shutdown = true;
			break;

		default:
			log("unexpected event id");
			break;
		}
	}

exit:
	log("exiting capture thread");

	if (audioses_module != (uintptr_t)NULL)
		CloseHandle((HANDLE)audioses_module);

	destroy_data();
	destroy_events();

	return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
	UNUSED_PARAMETER(reserved);
	if (reason == DLL_PROCESS_ATTACH) {
		log("attach");

		wchar_t name[MAX_PATH];
		GetModuleFileNameW(hinst, name, MAX_PATH);
		LoadLibraryW(name);

		capture_thread = CreateThread(
			NULL, 0, (LPTHREAD_START_ROUTINE)main_capture_thread,
			NULL, 0, 0);

		if (capture_thread == NULL)
			return FALSE;
	} else if (reason == DLL_PROCESS_DETACH) {
		log("detach");

		if (capture_thread) {
			if (events[HOOK_WO_EVENT_SHUTDOWN] != NULL)
				SetEvent(events[HOOK_WO_EVENT_SHUTDOWN]);

			CloseHandle(capture_thread);
		}

		if (audioses_module != (uintptr_t)NULL)
			CloseHandle((HANDLE)audioses_module);

		destroy_data();
		destroy_events();
	}

	return TRUE;
}

__declspec(dllexport) LRESULT CALLBACK
	dummy_debug_proc(int code, WPARAM wparam, LPARAM lparam)
{
	static bool hooking = true;

	MSG *msg = (MSG *)lparam;
	if (hooking && msg->message == (WM_USER + 432)) {
		HMODULE user32 = GetModuleHandleW(L"USER32");
		BOOL(WINAPI * unhook_windows_hook_ex)(HHOOK) = NULL;

		unhook_windows_hook_ex = get_obfuscated_func(
			user32, "VojeleY`bdgxvM`hhDz", 0x7F55F80C9EE3A213ULL);

		if (unhook_windows_hook_ex)
			unhook_windows_hook_ex((HHOOK)msg->lParam);

		hooking = false;
	}

	return CallNextHookEx(0, code, wparam, lparam);
}
