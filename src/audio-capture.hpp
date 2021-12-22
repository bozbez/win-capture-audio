#pragma once

#include <optional>
#include <stdio.h>

#include <windows.h>

#include <obs.h>
#include <util/darray.h>

#include "common.hpp"
#include "window-helpers.hpp"
#include "audio-capture-helper.hpp"

/* clang-format off */

#define SETTING_MODE                   "mode"

#define SETTING_WINDOW                 "window"
#define SETTING_WINDOW_PRIORITY        "window_priority"

#define SETTING_EXCLUDE_PROCESS_TREE   "exclude_process_tree"

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

#define HOTKEY_START                   "hotkey_start"
#define HOTKEY_STOP                    "hotkey_stop"

/* clang-format on */

enum mode { MODE_WINDOW, MODE_HOTKEY };

struct audio_capture_config_t {
	enum mode mode;
	HWND hotkey_window;

	window_info_t window_info;
	enum window_priority priority;

	bool exclude_process_tree;
};

struct audio_capture_context_t {
	bool worker_initialized;
	HANDLE worker_thread;

	CRITICAL_SECTION config_section;
	audio_capture_config_t config;

	obs_hotkey_pair_id hotkey_pair;
	obs_source_t *source;

	CRITICAL_SECTION timer_section;
	HANDLE timer;
	HANDLE timer_queue;

	HANDLE events[NUM_EVENTS];

	std::optional<AudioCaptureHelper> helper;

	HANDLE process;
	DWORD process_id;
	DWORD next_process_id;

	bool window_selected;
	bool exclude_process_tree;
};