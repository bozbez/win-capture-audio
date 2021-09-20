#include <media-io/audio-io.h>
#include <obs.h>
#include <stdint.h>
#include <util/darray.h>
#include <windows.h>
#include <math.h>
#include <stdio.h>
#include <string.h>

#include <mmreg.h>
#include <audiopolicy.h>
#include <audioclientactivationparams.h>

#include <obs-module.h>
#include <obs-data.h>
#include <obs-properties.h>
#include <util/bmem.h>
#include <util/platform.h>

#include "window-helpers.h"
#include "audio-capture.h"
#include "obfuscate.h"

VOID CALLBACK set_update(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
	audio_capture_context_t *ctx = lpParam;
	SetEvent(ctx->events[EVENT_UPDATE]);
}

void set_update_timer(audio_capture_context_t *ctx, float interval)
{
	EnterCriticalSection(&ctx->timer_section);

	EnterCriticalSection(&ctx->config_section);
	DWORD time_millis =
		(DWORD)(ctx->config.retry_interval * interval * 1000.0);
	LeaveCriticalSection(&ctx->config_section);

	if (ctx->timer != NULL) {
		DeleteTimerQueueTimer(ctx->timer_queue, ctx->timer,
				      INVALID_HANDLE_VALUE);
		ctx->timer = NULL;
	}

	// debug("setting timer for %ld millis", time_millis);
	CreateTimerQueueTimer(&ctx->timer, ctx->timer_queue, set_update, ctx,
			      time_millis, 0, WT_EXECUTEINTIMERTHREAD);

	LeaveCriticalSection(&ctx->timer_section);
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

static void destroy_data(audio_capture_context_t *ctx)
{
	if (ctx->data != NULL) {
		UnmapViewOfFile((void **)ctx->data);
		ctx->data = NULL;
	}

	safe_close_handle(&ctx->data_map);
}

static bool init_data(audio_capture_context_t *ctx)
{

	wchar_t name[MAX_PATH];
	format_name_tag(name, HELPER_DATA_NAME, ctx->tag);
	ctx->data_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
					   PAGE_READWRITE, 0,
					   sizeof(audio_capture_helper_data_t),
					   name);
	if (ctx->data_map == NULL) {
		error("failed to create file mapping with name: %ls", name);
		return false;
	}

	ctx->data = MapViewOfFile(ctx->data_map, FILE_MAP_ALL_ACCESS, 0, 0,
				  sizeof(audio_capture_helper_data_t));
	if (ctx->data == NULL) {
		error("failed to map view of data map");
		return false;
	}

	return true;
}

static void destroy_helper_events(audio_capture_context_t *ctx)
{
	for (int i = HELPER_WO_EVENTS_START; i < HELPER_EVENTS_END; ++i)
		safe_close_handle(&ctx->events[i]);
}

static bool init_helper_events(audio_capture_context_t *ctx)
{
	for (int i = HELPER_WO_EVENTS_START; i < HELPER_EVENTS_END; ++i) {
		wchar_t name[MAX_PATH];
		format_name_tag(name, event_names[i], ctx->tag);

		ctx->events[i] = CreateEventW(NULL, FALSE, FALSE, name);
		if (ctx->events[i] == NULL) {
			error("failed to create helper event");
			return false;
		}
	}

	return true;
}

static void start_capture(audio_capture_context_t *ctx)
{
	ctx->tag = bzalloc(MAX_PATH * sizeof(char));
	format_tag(ctx->tag, ctx->process_id);

	debug("tag is: %s", ctx->tag);

	if (!init_helper_events(ctx)) {
		error("failed to init helper events");
		return;
	}

	if (!init_data(ctx)) {
		error("failed to init shmem data");
		return;
	}

	char *helper_path = obs_module_file("audio-capture-helper.exe");
	if (!check_file_integrity(ctx, helper_path, "helper"))
		return;

	wchar_t *helper_path_w;
	os_utf8_to_wcs_ptr(helper_path, 0, &helper_path_w);

	wchar_t *command_line_w = bzalloc(4096 * sizeof(wchar_t));
	swprintf(command_line_w, 4096, L"\"%s\" %lu %S %S", helper_path_w,
		 ctx->process_id,
		 ctx->exclude_process_tree ? "exclude" : "include", ctx->tag);

	STARTUPINFOW startup_info = {0};
	PROCESS_INFORMATION process_info = {0};

	startup_info.cb = sizeof(startup_info);

	debug("launching helper with command line: %ls", command_line_w);
	bool success = CreateProcessW(NULL, command_line_w, NULL, NULL, false,
				      CREATE_NO_WINDOW, NULL, NULL,
				      &startup_info, &process_info);

	if (success) {
		safe_close_handle(&process_info.hThread);

		ctx->helper_process_id = process_info.dwProcessId;
		ctx->helper_process = process_info.hProcess;
	} else {
		error("failed to create helper process");
	}

	ctx->process = open_process(PROCESS_QUERY_INFORMATION | SYNCHRONIZE,
				    false, ctx->process_id);

	if (ctx->process == NULL)
		warn("failed to open target process, can't detect termination");

	bfree(command_line_w);
	bfree(helper_path_w);
}

static void stop_capture(audio_capture_context_t *ctx)
{
	if (ctx->helper_process_id != 0) {
		SetEvent(ctx->events[HELPER_WO_EVENT_SHUTDOWN]);
		WaitForSingleObject(ctx->helper_process, INFINITE);

		ResetEvent(ctx->events[HELPER_WO_EVENT_SHUTDOWN]);
	}

	ctx->helper_process_id = 0;
	safe_close_handle(&ctx->helper_process);
	safe_close_handle(&ctx->process);

	destroy_helper_events(ctx);
	destroy_data(ctx);

	bfree(ctx->tag);
	ctx->tag = NULL;
}

static void audio_capture_worker_recapture(audio_capture_context_t *ctx)
{
	stop_capture(ctx);
	ctx->process_id = ctx->next_process_id;

	if (ctx->process_id != 0)
		start_capture(ctx);
	else if (ctx->window_selected)
		set_update_timer(ctx, RECAPTURE_INTERVAL_DEFAULT);
}

static void audio_capture_worker_update(audio_capture_context_t *ctx)
{
	EnterCriticalSection(&ctx->config_section);

	ctx->exclude_process_tree = ctx->config.exclude_process_tree;

	if (ctx->config.mode == MODE_HOTKEY) {
		if (ctx->config.hotkey_window != NULL) {
			ctx->window_selected = true;
			GetWindowThreadProcessId(ctx->config.hotkey_window,
						 &ctx->next_process_id);
		} else {
			ctx->window_selected = false;
			ctx->next_process_id = 0;
		}

		goto exit;
	}

	if (ctx->config.window_info.title == NULL) {
		ctx->next_process_id = 0;
		ctx->window_selected = false;

		goto exit;
	}

	ctx->window_selected = true;
	HWND window = window_info_get_window(&ctx->config.window_info,
					     ctx->config.priority);

	if (window != NULL)
		GetWindowThreadProcessId(window, &ctx->next_process_id);
	else
		ctx->next_process_id = 0;

	if (ctx->next_process_id != 0) {
		debug("resolved window: \"%s\" \"%s\" \"%s\" to PID %lu",
		      ctx->config.window_info.title,
		      ctx->config.window_info.class,
		      ctx->config.window_info.executable, ctx->next_process_id);
	}

exit:
	LeaveCriticalSection(&ctx->config_section);
	audio_capture_worker_recapture(ctx);
}

static void audio_capture_worker_forward(audio_capture_context_t *ctx)
{
	static uint8_t data[HELPER_DATA_SIZE];

	if (InterlockedCompareExchange(&ctx->data->lock, 1, 0) != 0) {
		warn("failed to acquire data lock, dropping");
		return;
	}

	for (int packet = 0; packet < ctx->data->num_packets; ++packet) {
		struct obs_source_audio audio = {
			.data[0] = (uint8_t*)ctx->data->data[packet],
			.frames = ctx->data->frames[packet],

			.speakers = ctx->data->speakers,
			.format = ctx->data->format,
			.samples_per_sec = ctx->data->samples_per_sec,

			.timestamp = ctx->data->timestamp[packet]};

		if (audio.format == AUDIO_FORMAT_UNKNOWN)
			warn("unknown audio format");

		if (audio.speakers == SPEAKERS_UNKNOWN)
			warn("unknown audio channel configuration");

		obs_source_output_audio(ctx->source, &audio);
	}

	ctx->data->num_packets = 0;
	InterlockedExchange(&ctx->data->lock, 0);
}

static bool audio_capture_worker_tick(audio_capture_context_t *ctx,
				      int event_id)
{
	bool shutdown = false;

	switch (event_id) {
	case HELPER_EVENT_DATA:
		audio_capture_worker_forward(ctx);
		break;

	case EVENT_SHUTDOWN:
		debug("shutting down");

		stop_capture(ctx);
		shutdown = true;

		break;

	case EVENT_UPDATE:
		audio_capture_worker_update(ctx);
		break;

	case EVENT_PROCESS_TARGET:
		debug("target process died");

		safe_close_handle(&ctx->process);
		ctx->process_id = 0;

		audio_capture_worker_update(ctx);
		break;

	case EVENT_PROCESS_HELPER:
		DWORD code;
		bool success = GetExitCodeProcess(ctx->helper_process, &code);
		if (success)
			warn("helper died with exit code: %lu", code);
		else
			warn("helper died and failed to get exit code");

		safe_close_handle(&ctx->helper_process);
		ctx->helper_process_id = 0;

		set_update_timer(ctx, RECAPTURE_INTERVAL_ERROR);
		break;

	default:
		error("unexpected event id");

		stop_capture(ctx);
		shutdown = true;

		break;
	}

	return shutdown;
}

static DWORD WINAPI audio_capture_worker_thread(LPVOID lpParam)
{
	audio_capture_context_t *ctx = lpParam;

	HANDLE *events = bzalloc((2 + NUM_EVENTS_TOTAL) * sizeof(HANDLE));

	bool shutdown = false;
	while (!shutdown) {
		for (int i = 0; i < NUM_EVENTS_TOTAL; ++i)
			events[i] = ctx->events[i];

		int num_proc_events = 0;
		if (ctx->process != NULL) {
			events[NUM_EVENTS_TOTAL + num_proc_events] =
				ctx->process;
			num_proc_events++;
		}

		if (ctx->helper_process != NULL) {
			events[NUM_EVENTS_TOTAL + num_proc_events] =
				ctx->helper_process;
			num_proc_events++;
		}

		int num_events = NUM_EVENTS + num_proc_events;
		int events_start = EVENTS_START;
		if (events[HELPER_EVENTS_START] != NULL) {
			num_events += NUM_HELPER_EVENTS;
			events_start = HELPER_EVENTS_START;
		}

		DWORD event_id = WaitForMultipleObjects(
			num_events, &events[events_start], FALSE, INFINITE);

		if (!(event_id >= WAIT_OBJECT_0 &&
		      event_id < WAIT_OBJECT_0 + num_events)) {
			error("unexpected event id: %d", event_id);
			return 1;
		}

		event_id += events_start - WAIT_OBJECT_0;

		// TODO make this less awkward?
		if (num_proc_events == 1 && event_id == EVENT_PROCESS_TARGET &&
		    ctx->process == NULL)
			event_id = EVENT_PROCESS_HELPER;

		shutdown = audio_capture_worker_tick(ctx, event_id);
	}

	bfree(events);
	return 0;
}

static void audio_capture_update(void *data, obs_data_t *settings)
{
	audio_capture_context_t *ctx = data;
	bool need_update = false;

	audio_capture_config_t new_config = {
		.mode = obs_data_get_int(settings, SETTING_MODE),
		.priority = obs_data_get_int(settings, SETTING_WINDOW_PRIORITY),
		.exclude_process_tree = obs_data_get_bool(
			settings, SETTING_EXCLUDE_PROCESS_TREE),
		.retry_interval = recapture_rate_to_float(
			obs_data_get_int(settings, SETTING_RECAPTURE_RATE)),
	};

	const char *window = obs_data_get_string(settings, SETTING_WINDOW);
	build_window_strings(window, &new_config.window_info);

	EnterCriticalSection(&ctx->config_section);

	if (new_config.mode == MODE_HOTKEY) {
		if (ctx->config.mode != new_config.mode)
			ctx->config.hotkey_window = NULL;
	} else {
		if (window_info_cmp(&new_config.window_info,
				    &ctx->config.window_info)) {
			ctx->config.window_info = new_config.window_info;
			need_update = true;
		} else {
			window_info_destroy(&new_config.window_info);
		}

		if (ctx->config.priority != new_config.priority) {
			ctx->config.priority = new_config.priority;
			need_update = true;
		}
	}

	if (ctx->config.mode != new_config.mode) {
		ctx->config.mode = new_config.mode;
		need_update = true;
	}

	if (ctx->config.exclude_process_tree !=
	    new_config.exclude_process_tree) {
		ctx->config.exclude_process_tree =
			new_config.exclude_process_tree;
		need_update = true;
	}

	if (ctx->config.retry_interval != new_config.retry_interval) {
		ctx->config.retry_interval = new_config.retry_interval;
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
		debug("activate hotkey pressed");
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
		debug("deactivate hotkey pressed");
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
	if (ctx == NULL)
		return;

	if (ctx->worker_initialized) {
		SetEvent(ctx->events[EVENT_SHUTDOWN]);
		WaitForSingleObject(ctx->worker_thread, INFINITE);
	}

	safe_close_handle(&ctx->worker_thread);

	if (ctx->timer != NULL)
		DeleteTimerQueueTimer(ctx->timer_queue, ctx->timer, NULL);

	if (ctx->timer_queue != NULL)
		DeleteTimerQueue(ctx->timer_queue);

	for (int i = HELPER_WO_EVENTS_START; i < EVENTS_END; ++i)
		safe_close_handle(&ctx->events[i]);

	if (ctx->hotkey_pair)
		obs_hotkey_pair_unregister(ctx->hotkey_pair);

	window_info_destroy(&ctx->config.window_info);

	DeleteCriticalSection(&ctx->config_section);
	DeleteCriticalSection(&ctx->timer_section);

	bfree(ctx);
}

static void *audio_capture_create(obs_data_t *settings, obs_source_t *source)
{
	UNUSED_PARAMETER(settings);

	audio_capture_context_t *ctx = bzalloc(sizeof(audio_capture_context_t));
	ctx->source = source;

	InitializeCriticalSection(&ctx->config_section);
	InitializeCriticalSection(&ctx->timer_section);

	ctx->timer_queue = CreateTimerQueue();
	if (ctx->timer_queue == NULL) {
		error("failed to create timer queue");
		goto fail;
	}

	for (int i = EVENTS_START; i < EVENTS_END; ++i) {
		ctx->events[i] = CreateEventW(NULL, FALSE, FALSE, NULL);
		if (ctx->events[i] == NULL) {
			error("failed to create event");
			goto fail;
		}
	}

	ctx->hotkey_pair = obs_hotkey_pair_register_source(
		ctx->source, HOTKEY_START, TEXT_HOTKEY_START, HOTKEY_STOP,
		TEXT_HOTKEY_STOP, hotkey_start, hotkey_stop, ctx, ctx);

	audio_capture_update(ctx, settings);

	ctx->worker_thread = CreateThread(NULL, 0, audio_capture_worker_thread,
					  ctx, 0, NULL);
	if (ctx->worker_thread == NULL) {
		error("failed to create worker thread");
		goto fail;
	}

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
	window_info_t info = {NULL, NULL, NULL};
	struct dstr desc = {0};

	build_window_strings(val, &info);

	dstr_printf(&desc, "[%s]: %s", info.executable, info.title);
	obs_property_list_insert_string(p, idx, desc.array, val);
	obs_property_list_item_disable(p, idx, true);

	dstr_free(&desc);
	window_info_destroy(&info);
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

	// Exclude process tree setting
	p = obs_properties_add_bool(ps, SETTING_EXCLUDE_PROCESS_TREE,
				    TEXT_EXCLUDE_PROCESS_TREE);

	// Recapture rate setting
	p = obs_properties_add_list(ps, SETTING_RECAPTURE_RATE,
				    TEXT_RECAPTURE_RATE, OBS_COMBO_TYPE_LIST,
				    OBS_COMBO_FORMAT_INT);

	obs_property_list_add_int(p, TEXT_RECAPTURE_RATE_SLOW,
				  RECAPTURE_RATE_SLOW);
	obs_property_list_add_int(p, TEXT_RECAPTURE_RATE_NORMAL,
				  RECAPTURE_RATE_NORMAL);
	obs_property_list_add_int(p, TEXT_RECAPTURE_RATE_FAST,
				  RECAPTURE_RATE_FAST);
	obs_property_list_add_int(p, TEXT_RECAPTURE_RATE_FASTEST,
				  RECAPTURE_RATE_FASTEST);

	return ps;
}

static void audio_capture_defaults(obs_data_t *settings)
{
	obs_data_set_default_int(settings, SETTING_MODE, MODE_WINDOW);
	obs_data_set_default_string(settings, SETTING_WINDOW, "");
	obs_data_set_default_int(settings, SETTING_WINDOW_PRIORITY,
				 WINDOW_PRIORITY_EXE);
	obs_data_set_default_bool(settings, SETTING_EXCLUDE_PROCESS_TREE,
				  false);
	obs_data_set_default_int(settings, SETTING_RECAPTURE_RATE,
				 RECAPTURE_RATE_NORMAL);
}

static const char *audio_capture_get_name(void *type_data)
{
	UNUSED_PARAMETER(type_data);
	return TEXT_NAME;
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