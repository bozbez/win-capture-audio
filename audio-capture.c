#include <math.h>
#include <windows.h>
#include <mmreg.h>

#include <obs.h>
#include <obs-module.h>
#include <obs-data.h>
#include <obs-properties.h>
#include <util/bmem.h>
#include <util/platform.h>

#include "media-io/audio-io.h"
#include "window-helpers.h"
#include "hook-info.h"
#include "obfuscate.h"
#include "inject-library.h"

#define do_log(level, format, ...)                   \
	blog(level, "[audio-capture: '%s'] " format, \
	     obs_source_get_name(ctx->source), ##__VA_ARGS__)

#define error(format, ...) do_log(LOG_ERROR, format, ##__VA_ARGS__)
#define warn(format, ...) do_log(LOG_WARNING, format, ##__VA_ARGS__)
#define info(format, ...) do_log(LOG_INFO, format, ##__VA_ARGS__)
#define debug(format, ...) do_log(LOG_DEBUG, format, ##__VA_ARGS__)

/* clang-format off */

#define SETTING_MODE                "mode"

#define SETTING_WINDOW              "window"
#define SETTING_WINDOW_PRIORITY     "window_priority"

#define SETTING_USE_INDIRECT_HOOK   "use_indirect_hook"
#define SETTING_HOOK_RATE           "hook_rate"

#define TEXT_MODE                   obs_module_text("Mode")
#define TEXT_MODE_WINDOW            obs_module_text("Mode.Window")
#define TEXT_MODE_HOTKEY            obs_module_text("Mode.Hotkey")

#define TEXT_WINDOW                 obs_module_text("Window")
#define TEXT_WINDOW_PRIORITY        obs_module_text("Window.Priority")
#define TEXT_WINDOW_PRIORITY_TITLE  obs_module_text("Window.Priority.Title")
#define TEXT_WINDOW_PRIORITY_CLASS  obs_module_text("Window.Priority.Class")
#define TEXT_WINDOW_PRIORITY_EXE    obs_module_text("Window.Priority.Exe")

#define TEXT_HOTKEY_START           obs_module_text("Hotkey.Start")
#define TEXT_HOTKEY_STOP            obs_module_text("Hotkey.Stop")

#define TEXT_USE_INDIRECT_HOOK      obs_module_text("UseIndirectHook")

#define TEXT_HOOK_RATE              obs_module_text("HookRate")
#define TEXT_HOOK_RATE_SLOW         obs_module_text("HookRate.Slow")
#define TEXT_HOOK_RATE_NORMAL       obs_module_text("HookRate.Normal")
#define TEXT_HOOK_RATE_FAST         obs_module_text("HookRate.Fast")
#define TEXT_HOOK_RATE_FASTEST      obs_module_text("HookRate.Fastest")

#define HOTKEY_START                "hotkey_start"
#define HOTKEY_STOP                 "hotkey_stop"

#define HOOK_INTERVAL_IMMEDIATE     0.0f
#define HOOK_INTERVAL_PING          0.1f
#define HOOK_INTERVAL_DEFAULT       2.0f
#define HOOK_INTERVAL_ERROR         4.0f

/* clang-format on */

enum mode { MODE_WINDOW, MODE_HOTKEY };

enum hook_rate {
	HOOK_RATE_SLOW,
	HOOK_RATE_NORMAL,
	HOOK_RATE_FAST,
	HOOK_RATE_FASTEST
};

typedef struct window_info {
	char *title;
	char *class;
	char *executable;
} window_info_t;

typedef struct audio_capture_config {
	enum mode mode;
	HWND hotkey_window;

	window_info_t window_info;
	enum window_priority priority;

	float retry_interval;
	bool use_indirect_hook;
} audio_capture_config_t;

typedef struct audio_capture_context {
	bool worker_initialized;
	HANDLE worker_thread;

	CRITICAL_SECTION config_section;
	audio_capture_config_t config;

	obs_hotkey_pair_id hotkey_pair;
	obs_source_t *source;

	HANDLE timer;
	HANDLE timer_queue;

	HANDLE hook_data_map;
	volatile audio_hook_data_t *hook_data;

	HANDLE events[NUM_EVENTS_TOTAL];

	DWORD process_id;
	DWORD thread_id;

	DWORD next_process_id;
	DWORD next_thread_id;

	HANDLE injector_process;
	HANDLE target_process;

	bool injected;
	bool active;

	bool target_opened;
	bool target_is_64bit;

	bool use_indirect_hook;
} audio_capture_context_t;

static inline float hook_rate_to_float(enum hook_rate rate)
{
	switch (rate) {
	case HOOK_RATE_SLOW:
		return 2.0f;
	case HOOK_RATE_FAST:
		return 0.5f;
	case HOOK_RATE_FASTEST:
		return 0.1f;
	case HOOK_RATE_NORMAL:
		/* FALLTHROUGH */
	default:
		return 1.0f;
	}
}

static void window_info_destroy(window_info_t *w)
{
	bfree(w->title);
	bfree(w->class);
	bfree(w->executable);
}

static bool window_info_cmp(window_info_t *wa, window_info_t *wb)
{
	if (wa->title == NULL && wb->title == NULL)
		return false;
	else if (wa->title == NULL || wb->title == NULL)
		return true;

	return strcmp(wa->title, wb->title) || strcmp(wa->class, wb->class) ||
	       strcmp(wa->executable, wb->executable);
}

static HWND window_info_get_window(window_info_t *w,
				   enum window_priority priority)
{
	HWND window = NULL;

	if (strcmp(w->class, "dwm") == 0) {
		wchar_t class_w[512];
		os_utf8_to_wcs(w->class, 0, class_w, 512);
		window = FindWindowW(class_w, NULL);
	} else {
		window = find_window(INCLUDE_MINIMIZED, priority, w->class,
				     w->title, w->executable);
	}

	return window;
}

VOID CALLBACK set_rehook(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
	audio_capture_context_t *ctx = lpParam;
	SetEvent(ctx->events[EVENT_REHOOK]);
}

void set_rehook_timer(audio_capture_context_t *ctx, float interval)
{
	EnterCriticalSection(&ctx->config_section);
	DWORD time_millis =
		(DWORD)(ctx->config.retry_interval * interval * 1000.0);
	LeaveCriticalSection(&ctx->config_section);

	if (ctx->timer != NULL) {
		DeleteTimerQueueTimer(ctx->timer_queue, ctx->timer,
				      INVALID_HANDLE_VALUE);
		ctx->timer = NULL;
	}

	info("%s: setting timer for %ld millis", __func__, time_millis);
	CreateTimerQueueTimer(&ctx->timer, ctx->timer_queue, set_rehook, ctx,
			      time_millis, 0, WT_EXECUTEINTIMERTHREAD);
}

void cancel_rehook_timer(audio_capture_context_t *ctx)
{
	if (ctx->timer != NULL) {
		DeleteTimerQueueTimer(ctx->timer_queue, ctx->timer,
				      INVALID_HANDLE_VALUE);
		ctx->timer = NULL;
	}
}

static wchar_t *get_string_error(DWORD err)
{
	static wchar_t buf[256];
	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM |
			       FORMAT_MESSAGE_IGNORE_INSERTS,
		       NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		       buf, (sizeof(buf) / sizeof(wchar_t)), NULL);

	return buf;
}

static bool init_hook_data(audio_capture_context_t *ctx)
{
	wchar_t name[MAX_PATH];
	format_name_pid(name, HOOK_DATA_NAME, ctx->process_id);

	ctx->hook_data_map =
		CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,
				   0, sizeof(audio_hook_data_t), name);

	if (!ctx->hook_data_map) {
		error("%s: failed to create file mapping with name: %ls: %ls",
		      __func__, name, get_string_error(GetLastError()));
		return false;
	}

	ctx->hook_data = MapViewOfFile(ctx->hook_data_map, FILE_MAP_ALL_ACCESS,
				       0, 0, sizeof(audio_hook_data_t));

	if (!ctx->hook_data) {
		CloseHandle(ctx->hook_data_map);
		ctx->hook_data_map = NULL;

		error("%s: failed to create file map view (%s)",
		      get_string_error(GetLastError()));

		return false;
	}

	info("%s: successfully created file mapping", __func__);
	return true;
}

static void destroy_hook_data(audio_capture_context_t *ctx)
{
	if (ctx->hook_data != NULL) {
		UnmapViewOfFile((void *)ctx->hook_data);
		ctx->hook_data = NULL;
	}

	if (ctx->hook_data_map != NULL) {
		CloseHandle(ctx->hook_data_map);
		ctx->hook_data_map = NULL;
	}
}

static bool init_hook_events(audio_capture_context_t *ctx)
{
	for (int i = HOOK_WO_EVENTS_START; i < HOOK_EVENTS_END; ++i) {
		wchar_t name[MAX_PATH];
		format_name_pid(name, event_info[i].name, ctx->process_id);

		ctx->events[i] =
			CreateEventW(NULL, event_info[i].reset, FALSE, name);

		if (ctx->events[i] == NULL)
			return false;
	}

	return true;
}

static void destroy_hook_events(audio_capture_context_t *ctx)
{
	for (int i = HOOK_WO_EVENTS_START; i < HOOK_EVENTS_END; ++i) {
		if (ctx->events[i] != NULL)
			CloseHandle(ctx->events[i]);

		ctx->events[i] = NULL;
	}
}

static inline HANDLE open_process(DWORD desired_access, bool inherit_handle,
				  DWORD process_id)
{
	typedef HANDLE(WINAPI * PFN_OpenProcess)(DWORD, BOOL, DWORD);

	static HMODULE kernel32_handle = NULL;
	static PFN_OpenProcess open_process_proc = NULL;

	if (!kernel32_handle)
		kernel32_handle = GetModuleHandleW(L"kernel32");

	if (!open_process_proc)
		open_process_proc = (PFN_OpenProcess)get_obfuscated_func(
			kernel32_handle, "NuagUykjcxr", 0x1B694B59451ULL);

	return open_process_proc(desired_access, inherit_handle, process_id);
}

static inline bool is_64bit_windows(void)
{
#ifdef _WIN64
	return true;
#else
	BOOL x86 = false;
	bool success = !!IsWow64Process(GetCurrentProcess(), &x86);
	return success && !!x86;
#endif
}

static inline bool is_64bit_process(HANDLE process)
{
	BOOL x86 = true;
	if (is_64bit_windows()) {
		bool success = !!IsWow64Process(process, &x86);
		if (!success) {
			return false;
		}
	}

	return !x86;
}

static bool open_target_process(audio_capture_context_t *ctx)
{
	ctx->target_process =
		open_process(PROCESS_QUERY_INFORMATION | SYNCHRONIZE, false,
			     ctx->process_id);

	if (!ctx->target_process) {
		warn("could not open process: %lu", ctx->process_id);
		return false;
	}

	ctx->target_opened = true;
	ctx->target_is_64bit = is_64bit_process(ctx->target_process);

	return true;
}

#define STOP_BEING_BAD                                                      \
	"  This is most likely due to security software. Please make sure " \
	"that the OBS installation folder is excluded/ignored in the "      \
	"settings of the security software you are using."

static bool check_file_integrity(audio_capture_context_t *ctx, const char *file,
				 const char *name)
{
	DWORD error;
	HANDLE handle;
	wchar_t *w_file = NULL;

	if (!file || !*file) {
		warn("Audio capture %s not found." STOP_BEING_BAD, name);
		return false;
	}

	if (!os_utf8_to_wcs_ptr(file, 0, &w_file)) {
		warn("Could not convert file name to wide string");
		return false;
	}

	handle = CreateFileW(w_file, GENERIC_READ | GENERIC_EXECUTE,
			     FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	bfree(w_file);

	if (handle != INVALID_HANDLE_VALUE) {
		CloseHandle(handle);
		return true;
	}

	error = GetLastError();
	if (error == ERROR_FILE_NOT_FOUND) {
		warn("Audio capture file '%s' not found." STOP_BEING_BAD, file);
	} else if (error == ERROR_ACCESS_DENIED) {
		warn("Audio capture file '%s' could not be loaded." STOP_BEING_BAD,
		     file);
	} else {
		warn("Audio capture file '%s' could not be loaded: %lu." STOP_BEING_BAD,
		     file, error);
	}

	return false;
}

static inline int inject_library(HANDLE process, const wchar_t *dll)
{
	return inject_library_obf(process, dll, "D|hkqkW`kl{k\\osofj",
				  0xa178ef3655e5ade7, "[uawaRzbhh{tIdkj~~",
				  0x561478dbd824387c, "[fr}pboIe`dlN}",
				  0x395bfbc9833590fd, "\\`zs}gmOzhhBq",
				  0x12897dd89168789a, "GbfkDaezbp~X",
				  0x76aff7238788f7db);
}

static inline bool hook_direct(audio_capture_context_t *ctx,
			       const char *hook_path_rel)
{
	wchar_t hook_path_abs_w[MAX_PATH];
	wchar_t *hook_path_rel_w;

	os_utf8_to_wcs_ptr(hook_path_rel, 0, &hook_path_rel_w);
	if (!hook_path_rel_w) {
		warn("%s: could not convert string", __func__);
		return false;
	}

	wchar_t *path_ret =
		_wfullpath(hook_path_abs_w, hook_path_rel_w, MAX_PATH);
	bfree(hook_path_rel_w);

	if (path_ret == NULL) {
		warn("%s: could not make absolute path", __func__);
		return false;
	}

	info("%s: made absolute hook path: %ls", __func__, hook_path_abs_w);

	HANDLE process =
		open_process(PROCESS_ALL_ACCESS, false, ctx->process_id);
	if (!process) {
		warn("%s: could not open process: %s (%lu)", __func__,
		     ctx->config.window_info.executable, GetLastError());
		return false;
	}

	int ret = inject_library(process, hook_path_abs_w);
	CloseHandle(process);

	if (ret != 0) {
		warn("%s: inject failed: %d", __func__, ret);
		return false;
	}

	return true;
}

static inline bool create_inject_process(audio_capture_context_t *ctx,
					 const char *inject_path,
					 const char *hook_dll)
{
	wchar_t *command_line_w = bzalloc(4096 * sizeof(wchar_t));

	wchar_t *inject_path_w;
	wchar_t *hook_dll_w;

	bool indirect_hook = ctx->use_indirect_hook;

	PROCESS_INFORMATION process_info = {0};
	STARTUPINFOW startup_info = {0};
	bool success = false;

	os_utf8_to_wcs_ptr(inject_path, 0, &inject_path_w);
	os_utf8_to_wcs_ptr(hook_dll, 0, &hook_dll_w);

	startup_info.cb = sizeof(startup_info);

	swprintf(command_line_w, 4096, L"\"%s\" \"%s\" %lu %lu", inject_path_w,
		 hook_dll_w, (unsigned long)indirect_hook,
		 indirect_hook ? ctx->thread_id : ctx->process_id);

	info("%s: attempting to create helper process with args: \"%ls\"",
	     __func__, command_line_w);

	success = !!CreateProcessW(inject_path_w, command_line_w, NULL, NULL,
				   false, CREATE_NO_WINDOW, NULL, NULL,
				   &startup_info, &process_info);

	if (success) {
		CloseHandle(process_info.hThread);

		if (ctx->injector_process)
			CloseHandle(ctx->injector_process);

		ctx->injector_process = process_info.hProcess;

		info("%s: created injector process: %llu", __func__,
		     ctx->injector_process);
	} else {
		warn("%s: failed to create inject helper process: %lu",
		     __func__, GetLastError());
	}

	bfree(command_line_w);

	bfree(inject_path_w);
	bfree(hook_dll_w);

	return success;
}

static bool try_inject(audio_capture_context_t *ctx)
{
	info("%s: attempting to inject: process_id = %lu", __func__,
	     ctx->process_id);

	bool success = false;

	char *inject_path;
	char *hook_path;

	if (ctx->target_is_64bit) {
		info("%s: target is 64 bit", __func__);

		inject_path = obs_module_file("inject-helper64.exe");
		hook_path = obs_module_file("audio-hook64.dll");
	} else {
		info("%s: target is 32 bit", __func__);

		inject_path = obs_module_file("inject-helper32.exe");
		hook_path = obs_module_file("audio-hook32.dll");
	}

	info("%s: inject helper path: \"%s\", hook path: \"%s\"", __func__,
	     inject_path, hook_path);

	if (!check_file_integrity(ctx, inject_path, "inject helper"))
		goto exit;

	if (!check_file_integrity(ctx, hook_path, "graphics hook"))
		goto exit;

#ifdef _WIN64
	bool matching_architecture = ctx->target_is_64bit;
#else
	bool matching_architecture = !ctx->target_is_64bit;
#endif

	if (matching_architecture && !ctx->use_indirect_hook) {
		info("%s: attempting direct hook", __func__);
		success = hook_direct(ctx, hook_path);
	} else {
		info("%s: attempting %s helper hook", __func__,
		     ctx->use_indirect_hook ? "indirect" : "direct");
		success = create_inject_process(ctx, inject_path, hook_path);
	}

exit:
	bfree(inject_path);
	bfree(hook_path);

	return success;
}

static void try_unhook(audio_capture_context_t *ctx)
{
	if (ctx->target_process != NULL) {
		CloseHandle(ctx->target_process);
		ctx->target_process = NULL;
	}

	if (ctx->injector_process != NULL) {
		CloseHandle(ctx->injector_process);
		ctx->injector_process = NULL;
	}

	if (ctx->events[HOOK_WO_EVENT_STOP] != NULL) {
		info("%s: signalling hook shutdown", __func__);
		SetEvent(ctx->events[HOOK_WO_EVENT_STOP]);
	}

	destroy_hook_data(ctx);
	destroy_hook_events(ctx);

	ctx->injected = false;
	ctx->active = false;

	ctx->target_opened = false;
}

static void audio_capture_hook_update(audio_capture_context_t *ctx)
{
	EnterCriticalSection(&ctx->config_section);

	info("%s: settings update: mode = %d, "
	     "priority =  %d, retry_interval = %f",
	     __func__, ctx->config.mode, ctx->config.priority,
	     ctx->config.retry_interval);

	ctx->use_indirect_hook = ctx->config.use_indirect_hook;

	if (ctx->config.mode == MODE_HOTKEY) {
		info("%s: hotkey settings: hotkey_window = %lld", __func__,
		     ctx->config.hotkey_window);

		ctx->next_thread_id = GetWindowThreadProcessId(
			ctx->config.hotkey_window, &ctx->next_process_id);

		LeaveCriticalSection(&ctx->config_section);
		set_rehook_timer(ctx, HOOK_INTERVAL_IMMEDIATE);

		return;
	}

	if (ctx->config.window_info.title == NULL) {
		info("%s: window settings: no window", __func__);
		ctx->next_process_id = 0;

		LeaveCriticalSection(&ctx->config_section);
		set_rehook_timer(ctx, HOOK_INTERVAL_IMMEDIATE);

		return;
	}

	info("%s: window settings: title = %s, "
	     "class = %s, executable = %s",
	     __func__, ctx->config.window_info.title,
	     ctx->config.window_info.class, ctx->config.window_info.executable);

	HWND window = window_info_get_window(&ctx->config.window_info,
					     ctx->config.priority);

	ctx->next_thread_id =
		GetWindowThreadProcessId(window, &ctx->next_process_id);

	LeaveCriticalSection(&ctx->config_section);
	set_rehook_timer(ctx, HOOK_INTERVAL_IMMEDIATE);
}

bool audio_capture_hook_rehook(audio_capture_context_t *ctx)
{
	info("%s: rehook triggered: process_id = %lu, next_process_id = %lu",
	     __func__, ctx->process_id, ctx->next_process_id);

	if (ctx->next_process_id == 0) {
		try_unhook(ctx);
		return true;
	}

	if (ctx->injected && ctx->process_id == ctx->next_process_id) {
		if (!ctx->active) {
			SetEvent(ctx->events[HOOK_WO_EVENT_START]);
			set_rehook_timer(ctx, HOOK_INTERVAL_DEFAULT);
		}

		return true;
	}

	if (ctx->process_id != ctx->next_process_id) {
		try_unhook(ctx);

		ctx->process_id = ctx->next_process_id;
		ctx->thread_id = ctx->next_thread_id;

		if (!init_hook_data(ctx)) {
			error("%s: failed to create hook data", __func__);
			return false;
		}

		if (!init_hook_events(ctx)) {
			error("%s: failed to create hook events", __func__);
			return false;
		}

		SetEvent(ctx->events[HOOK_WO_EVENT_PING]);
		set_rehook_timer(ctx, HOOK_INTERVAL_PING);

		return true;
	}

	if (ctx->injector_process &&
	    WaitForSingleObject(ctx->injector_process, 0) == WAIT_OBJECT_0) {
		DWORD exit_code = 0;
		GetExitCodeProcess(ctx->injector_process, &exit_code);

		if (exit_code != 0) {
			warn("%s: last inject process failed: %ld", __func__,
			     (long)exit_code);
		} else {
			info("%s: last inject process succeeded!", __func__);
		}
	}

	if (!ctx->target_opened && !open_target_process(ctx)) {
		set_rehook_timer(ctx, HOOK_INTERVAL_ERROR);
		return true;
	}

	if (!ctx->injected && !try_inject(ctx)) {
		warn("%s: try_inject failed", __func__);
		set_rehook_timer(ctx, HOOK_INTERVAL_ERROR);
		return true;
	}

	SetEvent(ctx->events[HOOK_WO_EVENT_START]);
	set_rehook_timer(ctx, HOOK_INTERVAL_DEFAULT);

	return true;
}

static enum speaker_layout get_obs_speaker_layout(WAVEFORMATEXTENSIBLE *format)
{
	switch (format->Format.nChannels) {
	case 1:
		return SPEAKERS_MONO;
	case 2:
		return SPEAKERS_STEREO;
	case 3:
		return SPEAKERS_2POINT1;
	case 4:
		return SPEAKERS_4POINT0;
	case 5:
		return SPEAKERS_4POINT1;
	case 6:
		return SPEAKERS_5POINT1;
	case 8:
		return SPEAKERS_7POINT1;
	}

	return SPEAKERS_UNKNOWN;
}

static enum audio_format get_obs_pcm_format(int bits_per_sample)
{
	switch (bits_per_sample) {
	case 8:
		return AUDIO_FORMAT_U8BIT;
	case 16:
		return AUDIO_FORMAT_16BIT;
	case 32:
		return AUDIO_FORMAT_32BIT;
	};

	return AUDIO_FORMAT_UNKNOWN;
}

static enum audio_format get_obs_format(WAVEFORMATEXTENSIBLE *format)
{
	switch (format->Format.wFormatTag) {
	case WAVE_FORMAT_PCM:
		return get_obs_pcm_format(format->Format.wBitsPerSample);

	case WAVE_FORMAT_IEEE_FLOAT:
		return AUDIO_FORMAT_FLOAT;

	case WAVE_FORMAT_EXTENSIBLE:
		if (IsEqualGUID(&format->SubFormat,
				&KSDATAFORMAT_SUBTYPE_PCM)) {
			return get_obs_pcm_format(
				format->Format.wBitsPerSample);
		} else if (IsEqualGUID(&format->SubFormat,
				       &KSDATAFORMAT_SUBTYPE_IEEE_FLOAT)) {
			return AUDIO_FORMAT_FLOAT;
		}
	}

	return AUDIO_FORMAT_UNKNOWN;
}

static void audio_capture_hook_forward_data(audio_capture_context_t *ctx)
{
	if (InterlockedCompareExchange(&ctx->hook_data->lock, 1, 0) != 0) {
		warn("%s: couldn't acquire lock", __func__);
		return;
	}

	struct obs_source_audio audio;

	audio.data[0] = (uint8_t *)ctx->hook_data->data;
	audio.frames = ctx->hook_data->frames;

	audio.speakers = get_obs_speaker_layout(
		(WAVEFORMATEXTENSIBLE *)&ctx->hook_data->format);
	audio.format =
		get_obs_format((WAVEFORMATEXTENSIBLE *)&ctx->hook_data->format);
	audio.samples_per_sec = ctx->hook_data->format.Format.nSamplesPerSec;

	audio.timestamp = ctx->hook_data->timestamp;

	obs_source_output_audio(ctx->source, &audio);

	InterlockedExchange(&ctx->hook_data->lock, 0);
}

static bool audio_capture_tick(audio_capture_context_t *ctx, int event_id)
{
	bool shutdown = false;

	switch (event_id) {
	case EVENT_SHUTDOWN:
		info("%s: shutting down", __func__);

		try_unhook(ctx);
		shutdown = true;

		break;

	case EVENT_UPDATE:
		audio_capture_hook_update(ctx);
		break;

	case EVENT_REHOOK:
		shutdown = !audio_capture_hook_rehook(ctx);
		break;

	case HOOK_EVENT_READY:
		info("%s: hook ready", __func__);
		ctx->injected = true;

		break;

	case HOOK_EVENT_ACTIVE:
		info("%s: hook activated", __func__);
		ctx->active = true;
		cancel_rehook_timer(ctx);

		break;

	case HOOK_EVENT_DATA:
		audio_capture_hook_forward_data(ctx);

		break;

	default:
		error("%s: unexpected event id", __func__);

		try_unhook(ctx);
		shutdown = true;

		break;
	}

	return shutdown;
}

static DWORD WINAPI audio_capture_thread(LPVOID lpParam)
{
	audio_capture_context_t *ctx = lpParam;

	bool shutdown = false;
	while (!shutdown) {
		int num_events = NUM_EVENTS;
		int start_event = EVENTS_START;

		if (ctx->events[HOOK_EVENTS_START] != NULL) {
			num_events += NUM_HOOK_EVENTS;
			start_event = HOOK_EVENTS_START;
		}

		HANDLE *events = &ctx->events[start_event];
		DWORD event_id = WaitForMultipleObjects(num_events, events,
							FALSE, INFINITE);

		if (!(event_id >= WAIT_OBJECT_0 &&
		      event_id < WAIT_OBJECT_0 + num_events)) {
			error("%s: unexpected event id: %d", __func__,
			      event_id);
			return 1;
		}

		event_id -= WAIT_OBJECT_0;
		shutdown = audio_capture_tick(ctx, start_event + event_id);
	}

	return 0;
}

static void audio_capture_update(void *data, obs_data_t *settings)
{
	audio_capture_context_t *ctx = data;
	bool need_update = false;

	enum mode mode = obs_data_get_int(settings, SETTING_MODE);

	const char *window = obs_data_get_string(settings, SETTING_WINDOW);
	enum window_priority priority =
		obs_data_get_int(settings, SETTING_WINDOW_PRIORITY);

	bool use_indirect_hook =
		obs_data_get_bool(settings, SETTING_USE_INDIRECT_HOOK);

	enum hook_rate hook_rate =
		obs_data_get_int(settings, SETTING_HOOK_RATE);

	float retry_interval = hook_rate_to_float(hook_rate);

	EnterCriticalSection(&ctx->config_section);

	if (mode == MODE_HOTKEY) {
		if (ctx->config.mode != mode)
			ctx->config.hotkey_window = NULL;
	} else {
		window_info_t window_info = {NULL, NULL, NULL};
		build_window_strings(window, &window_info.class,
				     &window_info.title,
				     &window_info.executable);

		if (window_info_cmp(&window_info, &ctx->config.window_info)) {
			ctx->config.window_info = window_info;
			need_update = true;
		} else {
			window_info_destroy(&window_info);
		}

		if (ctx->config.priority != priority) {
			ctx->config.priority = priority;
			need_update = true;
		}
	}

	if (ctx->config.mode != mode) {
		ctx->config.mode = mode;
		need_update = true;
	}

	if (ctx->config.use_indirect_hook != use_indirect_hook) {
		ctx->config.use_indirect_hook = use_indirect_hook;
		need_update = true;
	}

	if (ctx->config.retry_interval != retry_interval) {
		ctx->config.retry_interval = retry_interval;
		need_update = true;
	}

	LeaveCriticalSection(&ctx->config_section);
	if (need_update)
		SetEvent(ctx->events[EVENT_UPDATE]);
}

static bool hotkey_start(void *data, obs_hotkey_pair_id id,
			 obs_hotkey_t *hotkey, bool pressed)
{
	UNUSED_PARAMETER(id);
	UNUSED_PARAMETER(hotkey);

	audio_capture_context_t *ctx = data;
	bool needs_update = false;

	EnterCriticalSection(&ctx->config_section);
	if (pressed && ctx->config.mode == MODE_HOTKEY) {
		info("Activate hotkey pressed");
		ctx->config.hotkey_window = GetForegroundWindow();
		needs_update = true;
	}
	LeaveCriticalSection(&ctx->config_section);

	if (needs_update)
		SetEvent(ctx->events[EVENT_UPDATE]);

	return true;
}

static bool hotkey_stop(void *data, obs_hotkey_pair_id id, obs_hotkey_t *hotkey,
			bool pressed)
{
	UNUSED_PARAMETER(id);
	UNUSED_PARAMETER(hotkey);

	audio_capture_context_t *ctx = data;
	bool needs_update = false;

	EnterCriticalSection(&ctx->config_section);
	if (pressed && ctx->config.mode == MODE_HOTKEY) {
		info("Deactivate hotkey pressed");
		ctx->config.hotkey_window = NULL;
	}
	LeaveCriticalSection(&ctx->config_section);

	if (needs_update)
		SetEvent(ctx->events[EVENT_UPDATE]);

	return true;
}

static void audio_capture_destroy(void *data)
{
	audio_capture_context_t *ctx = data;
	if (!ctx)
		return;

	try_unhook(ctx);

	if (ctx->timer != NULL)
		DeleteTimerQueueTimer(ctx->timer_queue, ctx->timer, NULL);

	if (ctx->timer_queue != NULL)
		DeleteTimerQueue(ctx->timer_queue);

	if (ctx->worker_initialized) {
		SetEvent(ctx->events[EVENT_SHUTDOWN]);
		WaitForSingleObject(ctx->worker_thread, INFINITE);
	}

	if (ctx->worker_thread != NULL)
		CloseHandle(ctx->worker_thread);

	for (int i = EVENTS_START; i < EVENTS_END; ++i) {
		if (ctx->events[i] != NULL)
			CloseHandle(ctx->events[i]);
	}

	if (ctx->hotkey_pair)
		obs_hotkey_pair_unregister(ctx->hotkey_pair);

	window_info_destroy(&ctx->config.window_info);

	DeleteCriticalSection(&ctx->config_section);
	bfree(ctx);
}

static void *audio_capture_create(obs_data_t *settings, obs_source_t *source)
{
	UNUSED_PARAMETER(settings);

	audio_capture_context_t *ctx = bzalloc(sizeof(audio_capture_context_t));
	ctx->source = source;

	InitializeCriticalSection(&ctx->config_section);

	ctx->timer_queue = CreateTimerQueue();
	if (ctx->timer_queue == NULL)
		goto fail;

	for (int i = EVENTS_START; i < EVENTS_END; ++i) {
		ctx->events[i] = CreateEventW(NULL, event_info[i].reset, FALSE,
					      event_info[i].name);
		if (ctx->events[i] == NULL)
			goto fail;
	}

	ctx->hotkey_pair = obs_hotkey_pair_register_source(
		ctx->source, HOTKEY_START, TEXT_HOTKEY_START, HOTKEY_STOP,
		TEXT_HOTKEY_STOP, hotkey_start, hotkey_stop, ctx, ctx);

	audio_capture_update(ctx, settings);

	ctx->worker_thread =
		CreateThread(NULL, 0, audio_capture_thread, ctx, 0, NULL);
	if (ctx->worker_thread == NULL)
		goto fail;

	ctx->worker_initialized = true;

	return ctx;

fail:
	audio_capture_destroy(ctx);
	return NULL;
}

static bool mode_callback(obs_properties_t *ps, obs_property_t *p,
			  obs_data_t *settings)
{
	int mode = obs_data_get_int(settings, SETTING_MODE);

	p = obs_properties_get(ps, SETTING_WINDOW);
	obs_property_set_visible(p, mode == MODE_WINDOW);

	p = obs_properties_get(ps, SETTING_WINDOW_PRIORITY);
	obs_property_set_visible(p, mode == MODE_WINDOW);

	return true;
}

static void insert_preserved_val(obs_property_t *p, const char *val, size_t idx)
{
	window_info_t w = {NULL, NULL, NULL};
	struct dstr desc = {0};

	build_window_strings(val, &w.class, &w.title, &w.executable);

	dstr_printf(&desc, "[%s]: %s", w.executable, w.title);
	obs_property_list_insert_string(p, idx, desc.array, val);
	obs_property_list_item_disable(p, idx, true);

	dstr_free(&desc);
	window_info_destroy(&w);
}

static bool check_window_property_setting(obs_properties_t *ps,
					  obs_property_t *p,
					  obs_data_t *settings, const char *val,
					  size_t idx)
{
	UNUSED_PARAMETER(ps);

	const char *cur_val;
	bool match = false;
	size_t i = 0;

	cur_val = obs_data_get_string(settings, val);
	if (!cur_val) {
		return false;
	}

	for (;;) {
		const char *val = obs_property_list_item_string(p, i++);
		if (!val)
			break;

		if (strcmp(val, cur_val) == 0) {
			match = true;
			break;
		}
	}

	if (cur_val && *cur_val && !match) {
		insert_preserved_val(p, cur_val, idx);
		return true;
	}

	return false;
}

static bool window_callback(obs_properties_t *ps, obs_property_t *p,
			    obs_data_t *settings)
{
	return check_window_property_setting(ps, p, settings, SETTING_WINDOW,
					     1);
}

static bool window_not_blacklisted(const char *title, const char *class,
				   const char *exe)
{
	UNUSED_PARAMETER(title);
	UNUSED_PARAMETER(class);

	return !is_blacklisted_exe(exe);
}

static obs_properties_t *audio_capture_properties(void *data)
{
	UNUSED_PARAMETER(data);

	obs_properties_t *ps = obs_properties_create();
	obs_property_t *p;

	// Mode setting (specific window or hotkey)
	p = obs_properties_add_list(ps, SETTING_MODE, TEXT_MODE,
				    OBS_COMBO_TYPE_LIST, OBS_COMBO_FORMAT_INT);

	obs_property_list_add_int(p, TEXT_MODE_WINDOW, MODE_WINDOW);
	obs_property_list_add_int(p, TEXT_MODE_HOTKEY, MODE_HOTKEY);

	obs_property_set_modified_callback(p, mode_callback);

	// Window setting
	p = obs_properties_add_list(ps, SETTING_WINDOW, TEXT_WINDOW,
				    OBS_COMBO_TYPE_LIST,
				    OBS_COMBO_FORMAT_STRING);

	obs_property_list_add_string(p, "", "");
	fill_window_list(p, INCLUDE_MINIMIZED, window_not_blacklisted);

	obs_property_set_modified_callback(p, window_callback);

	// Window match priority setting
	p = obs_properties_add_list(ps, SETTING_WINDOW_PRIORITY,
				    TEXT_WINDOW_PRIORITY, OBS_COMBO_TYPE_LIST,
				    OBS_COMBO_FORMAT_INT);

	obs_property_list_add_int(p, TEXT_WINDOW_PRIORITY_TITLE,
				  WINDOW_PRIORITY_TITLE);
	obs_property_list_add_int(p, TEXT_WINDOW_PRIORITY_CLASS,
				  WINDOW_PRIORITY_CLASS);
	obs_property_list_add_int(p, TEXT_WINDOW_PRIORITY_EXE,
				  WINDOW_PRIORITY_EXE);

	// Anti-cheat compatibility hook setting
	p = obs_properties_add_bool(ps, SETTING_USE_INDIRECT_HOOK,
				    TEXT_USE_INDIRECT_HOOK);

	// Hook rate setting
	p = obs_properties_add_list(ps, SETTING_HOOK_RATE, TEXT_HOOK_RATE,
				    OBS_COMBO_TYPE_LIST, OBS_COMBO_FORMAT_INT);

	obs_property_list_add_int(p, TEXT_HOOK_RATE_SLOW, HOOK_RATE_SLOW);
	obs_property_list_add_int(p, TEXT_HOOK_RATE_NORMAL, HOOK_RATE_NORMAL);
	obs_property_list_add_int(p, TEXT_HOOK_RATE_FAST, HOOK_RATE_FAST);
	obs_property_list_add_int(p, TEXT_HOOK_RATE_FASTEST, HOOK_RATE_FASTEST);

	return ps;
}

static void audio_capture_defaults(obs_data_t *settings)
{
	obs_data_set_default_int(settings, SETTING_MODE, MODE_WINDOW);
	obs_data_set_default_string(settings, SETTING_WINDOW, "");
	obs_data_set_default_int(settings, SETTING_WINDOW_PRIORITY,
				 WINDOW_PRIORITY_EXE);
	obs_data_set_default_bool(settings, SETTING_USE_INDIRECT_HOOK, true);
	obs_data_set_default_int(settings, SETTING_HOOK_RATE, HOOK_RATE_NORMAL);
}

static const char *audio_capture_get_name(void *type_data)
{
	UNUSED_PARAMETER(type_data);
	return "Application Audio Output Capture";
}

struct obs_source_info audio_capture_info = {
	.id = "audio_capture",
	.get_name = audio_capture_get_name,
	.icon_type = OBS_ICON_TYPE_AUDIO_OUTPUT,

	.type = OBS_SOURCE_TYPE_INPUT,
	.output_flags = OBS_SOURCE_AUDIO,

	.get_defaults = audio_capture_defaults,
	.get_properties = audio_capture_properties,
	.update = audio_capture_update,

	.create = audio_capture_create,
	.destroy = audio_capture_destroy,
};