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

#include "wil/result_macros.h"
#include "window-helpers.hpp"
#include "audio-capture.hpp"
#include "obfuscate.hpp"

VOID CALLBACK set_update(PVOID lpParam, BOOLEAN TimerOrWaitFired)
{
	auto *ctx = static_cast<audio_capture_context_t *>(lpParam);
	SetEvent(ctx->events[EVENT_UPDATE]);
}

void set_update_timer(audio_capture_context_t *ctx)
{
	EnterCriticalSection(&ctx->timer_section);

	if (ctx->timer != NULL) {
		DeleteTimerQueueTimer(ctx->timer_queue, ctx->timer,
				      INVALID_HANDLE_VALUE);
		ctx->timer = NULL;
	}

	CreateTimerQueueTimer(&ctx->timer, ctx->timer_queue, set_update, ctx,
			      2000, 0, WT_EXECUTEINTIMERTHREAD);

	LeaveCriticalSection(&ctx->timer_section);
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

static inline bool process_is_alive(DWORD pid)
{
	HANDLE process = open_process(
		PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, pid);
	if (process == NULL)
		return false;

	DWORD code;
	bool success = GetExitCodeProcess(process, &code);

	safe_close_handle(&process);
	return success && code == STILL_ACTIVE;
}

static void start_capture(audio_capture_context_t *ctx)
{
	try {
		ctx->helper.emplace(ctx->source, ctx->process_id,
				    !ctx->exclude_process_tree);
	} catch (wil::ResultException e) {
		error("failed to create helper... update Windows?");
		error("%s", e.what());
	}

	ctx->process =
		open_process(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
			     false, ctx->process_id);

	if (ctx->process == NULL)
		warn("failed to open target process, can't detect termination");
}

static void stop_capture(audio_capture_context_t *ctx)
{
	try {
		ctx->helper.reset();
	} catch (wil::ResultException e) {
		error("failed to destruct helper");
		error("%s", e.what());
	}
}

static void audio_capture_worker_recapture(audio_capture_context_t *ctx)
{
	stop_capture(ctx);
	ctx->process_id = ctx->next_process_id;

	if (ctx->process_id != 0)
		start_capture(ctx);
	else if (ctx->window_selected)
		set_update_timer(ctx);
}

static void audio_capture_worker_update(audio_capture_context_t *ctx)
{
	EnterCriticalSection(&ctx->config_section);
	const auto config = ctx->config;
	LeaveCriticalSection(&ctx->config_section);

	HWND window;
	ctx->exclude_process_tree = config.exclude_process_tree;

	if (config.mode == MODE_HOTKEY) {
		if (config.hotkey_window == NULL) {
			ctx->window_selected = false;
			ctx->next_process_id = 0;
			goto exit;
		}

		ctx->window_selected = true;
		GetWindowThreadProcessId(config.hotkey_window,
					 &ctx->next_process_id);

		if (!process_is_alive(ctx->next_process_id)) {
			EnterCriticalSection(&ctx->config_section);
			ctx->config.hotkey_window = NULL;
			LeaveCriticalSection(&ctx->config_section);

			ctx->window_selected = false;
			ctx->next_process_id = 0;
		}

		goto exit;
	}

	if (config.window_info.title == NULL) {
		ctx->next_process_id = 0;
		ctx->window_selected = false;

		goto exit;
	}

	ctx->window_selected = true;
	window = window_info_get_window(&config.window_info, config.priority);

	if (window != NULL)
		GetWindowThreadProcessId(window, &ctx->next_process_id);
	else
		ctx->next_process_id = 0;

	if (ctx->next_process_id != 0) {
		debug("resolved window: \"%s\" \"%s\" \"%s\" to PID %lu",
		      config.window_info.title, config.window_info.cls,
		      config.window_info.executable, ctx->next_process_id);
	}

exit:
	audio_capture_worker_recapture(ctx);
}

static bool audio_capture_worker_tick(audio_capture_context_t *ctx,
				      int event_id)
{
	bool shutdown = false;

	bool success;
	DWORD code;

	switch (event_id) {
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
	auto *ctx = static_cast<audio_capture_context_t *>(lpParam);

	HANDLE *events = static_cast<HANDLE *>(
		bzalloc((1 + NUM_EVENTS) * sizeof(HANDLE)));

	bool shutdown = false;
	while (!shutdown) {
		for (int i = 0; i < NUM_EVENTS; ++i)
			events[i] = ctx->events[i];

		int num_proc_events = 0;
		if (ctx->process != NULL) {
			events[NUM_EVENTS] = ctx->process;
			num_proc_events++;
		}

		int num_events = NUM_EVENTS + num_proc_events;
		DWORD event_id = WaitForMultipleObjects(num_events, events,
							FALSE, INFINITE);

		if (!(event_id >= WAIT_OBJECT_0 &&
		      event_id < WAIT_OBJECT_0 + num_events)) {
			error("unexpected event id: %d", event_id);
			return 1;
		}

		event_id -= WAIT_OBJECT_0;
		shutdown = audio_capture_worker_tick(ctx, event_id);
	}

	bfree(events);
	return 0;
}

static void audio_capture_update(void *data, obs_data_t *settings)
{
	auto *ctx = static_cast<audio_capture_context_t *>(data);
	bool need_update = false;

	audio_capture_config_t new_config = {
		.mode = (mode)obs_data_get_int(settings, SETTING_MODE),
		.priority = (window_priority)obs_data_get_int(
			settings, SETTING_WINDOW_PRIORITY),
		.exclude_process_tree = obs_data_get_bool(
			settings, SETTING_EXCLUDE_PROCESS_TREE),
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

	LeaveCriticalSection(&ctx->config_section);

	if (need_update)
		SetEvent(ctx->events[EVENT_UPDATE]);
}

static bool hotkey_start(void *data, obs_hotkey_pair_id id,
			 obs_hotkey_t *hotkey, bool pressed)
{
	UNUSED_PARAMETER(id);
	UNUSED_PARAMETER(hotkey);

	auto *ctx = static_cast<audio_capture_context_t *>(data);
	bool needs_update = false;

	EnterCriticalSection(&ctx->config_section);
	auto mode = ctx->config.mode;
	LeaveCriticalSection(&ctx->config_section);

	if (pressed && mode == MODE_HOTKEY) {
		debug("activate hotkey pressed");
		HWND new_window = GetForegroundWindow();
		if (is_uwp_window(new_window))
			new_window = get_uwp_actual_window(new_window);

		EnterCriticalSection(&ctx->config_section);
		if (ctx->config.hotkey_window != new_window) {
			ctx->config.hotkey_window = new_window;
			needs_update = true;
		}
		LeaveCriticalSection(&ctx->config_section);
	}

	if (needs_update)
		SetEvent(ctx->events[EVENT_UPDATE]);

	return true;
}

static bool hotkey_stop(void *data, obs_hotkey_pair_id id, obs_hotkey_t *hotkey,
			bool pressed)
{
	UNUSED_PARAMETER(id);
	UNUSED_PARAMETER(hotkey);

	auto *ctx = static_cast<audio_capture_context_t *>(data);
	bool needs_update = false;

	EnterCriticalSection(&ctx->config_section);
	if (pressed && ctx->config.mode == MODE_HOTKEY) {
		debug("deactivate hotkey pressed");
		ctx->config.hotkey_window = NULL;
		needs_update = true;
	}
	LeaveCriticalSection(&ctx->config_section);

	if (needs_update)
		SetEvent(ctx->events[EVENT_UPDATE]);

	return true;
}

static void audio_capture_destroy(void *data)
{
	auto *ctx = static_cast<audio_capture_context_t *>(data);
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

	auto *ctx = static_cast<audio_capture_context_t *>(
		bzalloc(sizeof(audio_capture_context_t)));
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

static bool window_not_blacklisted(const char *title, const char *cls,
				   const char *exe)
{
	UNUSED_PARAMETER(title);
	UNUSED_PARAMETER(cls);

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
}

static const char *audio_capture_get_name(void *type_data)
{
	UNUSED_PARAMETER(type_data);
	return TEXT_NAME;
}

struct obs_source_info audio_capture_info = {
	.id = "audio_capture",

	.type = OBS_SOURCE_TYPE_INPUT,
	.output_flags = OBS_SOURCE_AUDIO,

	.get_name = audio_capture_get_name,

	.create = audio_capture_create,
	.destroy = audio_capture_destroy,

	.get_defaults = audio_capture_defaults,
	.get_properties = audio_capture_properties,

	.update = audio_capture_update,

	.icon_type = OBS_ICON_TYPE_AUDIO_OUTPUT,
};
