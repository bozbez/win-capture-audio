#pragma once

#include <stdio.h>
#include <windows.h>

#include <obs.h>
#include <util/darray.h>

#include "common.h"
#include "window-helpers.h"

#define do_log(level, format, ...)                                  \
	do_log_source(ctx->source, level, "(%s) " format, __func__, \
		      ##__VA_ARGS__)

inline static void do_log_source(const obs_source_t *source, int level,
				 const char *format, ...)
{
	va_list args;
	va_start(args, format);

	const char *name = obs_source_get_name(source);
	int len = strlen(name);

	const char *format_source = len <= 8 ? "[audio-capture: '%s'] %s"
					     : "[audio-capture: '%.8s...'] %s";

	int len_full = strlen(format_source) + 12 + strlen(format);
	char *format_full = bzalloc(len_full);

	snprintf(format_full, len_full, format_source, name, format);
	blogva(level, format_full, args);

	bfree(format_full);
	va_end(args);
}

#define error(format, ...) do_log(LOG_ERROR, format, ##__VA_ARGS__)
#define warn(format, ...) do_log(LOG_WARNING, format, ##__VA_ARGS__)
#define info(format, ...) do_log(LOG_INFO, format, ##__VA_ARGS__)
#define debug(format, ...) do_log(LOG_INFO, format, ##__VA_ARGS__)

/* clang-format off */

#define SETTING_MODE                   "mode"

#define SETTING_WINDOW                 "window"
#define SETTING_WINDOW_PRIORITY        "window_priority"

#define SETTING_EXCLUDE_PROCESS_TREE   "exclude_process_tree"

#define SETTING_RECAPTURE_RATE         "recapture_rate"

#define TEXT_NAME                      obs_module_text("Name")

#define TEXT_MODE                      obs_module_text("Mode")
#define TEXT_MODE_WINDOW               obs_module_text("Mode.Window")
#define TEXT_MODE_HOTKEY               obs_module_text("Mode.Hotkey")

#define TEXT_WINDOW                    obs_module_text("Window")
#define TEXT_WINDOW_PRIORITY           obs_module_text("Window.Priority")
#define TEXT_WINDOW_PRIORITY_TITLE     obs_module_text("Window.Priority.Title")
#define TEXT_WINDOW_PRIORITY_CLASS     obs_module_text("Window.Priority.Class")
#define TEXT_WINDOW_PRIORITY_EXE       obs_module_text("Window.Priority.Exe")

#define TEXT_HOTKEY_START              obs_module_text("Hotkey.Start")
#define TEXT_HOTKEY_STOP               obs_module_text("Hotkey.Stop")

#define TEXT_EXCLUDE_PROCESS_TREE      obs_module_text("ExcludeProcessTree")

#define TEXT_RECAPTURE_RATE            obs_module_text("RecaptureRate")
#define TEXT_RECAPTURE_RATE_SLOW       obs_module_text("RecaptureRate.Slow")
#define TEXT_RECAPTURE_RATE_NORMAL     obs_module_text("RecaptureRate.Normal")
#define TEXT_RECAPTURE_RATE_FAST       obs_module_text("RecaptureRate.Fast")
#define TEXT_RECAPTURE_RATE_FASTEST    obs_module_text("RecaptureRate.Fastest")

#define HOTKEY_START                   "hotkey_start"
#define HOTKEY_STOP                    "hotkey_stop"

#define RECAPTURE_INTERVAL_DEFAULT      2.0f
#define RECAPTURE_INTERVAL_ERROR        4.0f

/* clang-format on */

enum mode { MODE_WINDOW, MODE_HOTKEY };

enum recapture_rate {
	RECAPTURE_RATE_SLOW,
	RECAPTURE_RATE_NORMAL,
	RECAPTURE_RATE_FAST,
	RECAPTURE_RATE_FASTEST
};

static inline float recapture_rate_to_float(enum recapture_rate rate)
{
	switch (rate) {
	case RECAPTURE_RATE_SLOW:
		return 2.0f;
	case RECAPTURE_RATE_FAST:
		return 0.5f;
	case RECAPTURE_RATE_FASTEST:
		return 0.1f;
	case RECAPTURE_RATE_NORMAL:
		/* FALLTHROUGH */
	default:
		return 1.0f;
	}
}

typedef struct audio_capture_config {
	enum mode mode;
	HWND hotkey_window;

	window_info_t window_info;
	enum window_priority priority;

	bool exclude_process_tree;
	float retry_interval;
} audio_capture_config_t;

typedef struct audio_capture_context {
	bool worker_initialized;
	HANDLE worker_thread;

	CRITICAL_SECTION config_section;
	audio_capture_config_t config;

	obs_hotkey_pair_id hotkey_pair;
	obs_source_t *source;

	CRITICAL_SECTION timer_section;
	HANDLE timer;
	HANDLE timer_queue;

	char *tag;
	HANDLE events[NUM_EVENTS_TOTAL];

	HANDLE data_map;
	volatile audio_capture_helper_data_t *data;

	HANDLE helper_process;
	DWORD helper_process_id;

	HANDLE process;
	DWORD process_id;
	DWORD next_process_id;

	bool window_selected;
	bool exclude_process_tree;
} audio_capture_context_t;