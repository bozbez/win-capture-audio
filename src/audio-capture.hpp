#pragma once

#include <cstdio>
#include <optional>
#include <tuple>

#include <windows.h>
#include <wil/resource.h>

#include <obs.h>
#include <util/darray.h>

#include "common.hpp"
#include "audio-capture-helper.hpp"
#include "session-monitor.hpp"

/* clang-format off */

#define SETTING_MODE                   "mode"

#define SETTING_SESSION                "session"

#define SETTING_EXCLUDE_PROCESS_TREE   "exclude_process_tree"

#define TEXT_NAME                      obs_module_text("Name")

#define TEXT_MODE                      obs_module_text("Mode")
#define TEXT_MODE_WINDOW               obs_module_text("Mode.Window")
#define TEXT_MODE_HOTKEY               obs_module_text("Mode.Hotkey")

#define TEXT_SESSION                   obs_module_text("Session")

#define TEXT_HOTKEY_START              obs_module_text("Hotkey.Start")
#define TEXT_HOTKEY_STOP               obs_module_text("Hotkey.Stop")

#define TEXT_EXCLUDE_PROCESS_TREE      obs_module_text("ExcludeProcessTree")

#define HOTKEY_START                   "hotkey_start"
#define HOTKEY_STOP                    "hotkey_stop"

/* clang-format on */

namespace CaptureEvents {
enum CaptureEvents {
	Shutdown = WM_USER,
	Update,
	SessionAdded,
	SessionExpired
};
}

enum mode { MODE_SESSION, MODE_HOTKEY };

struct AudioCaptureConfig {
	enum mode mode = MODE_SESSION;

	std::optional<std::tuple<DWORD, std::string>> session;
	HWND hotkey_window = NULL;

	bool exclude_process_tree = false;

	bool operator!=(const AudioCaptureConfig &other) const {
		if (other.mode != mode)
			return true;

		if (other.exclude_process_tree != exclude_process_tree)
			return true;

		if (mode == MODE_HOTKEY)
			return other.hotkey_window != hotkey_window;

		return other.session != session;
	}

	bool operator==(const AudioCaptureConfig &other) const {
		return !(*this != other);
	}
};

class AudioCapture {
private:
	std::thread worker_thread;
	DWORD worker_tid;
	wil::unique_event worker_ready{wil::EventOptions::ManualReset};

	wil::critical_section config_section;
	AudioCaptureConfig config;

	obs_hotkey_pair_id hotkey_pair;
	obs_source_t *source;

	std::optional<SessionMonitor> session_monitor;
	std::optional<AudioCaptureHelper> helper;

	wil::critical_section sessions_section;
	std::set<std::tuple<DWORD, std::string>> sessions;

	void StartCapture(DWORD pid, bool exclude);
	void StopCapture();

	void AddSession(const MSG &msg);
	void RemoveSession(const MSG &msg);

	void WorkerUpdate();

	bool Tick(const MSG &msg);
	void Run();

public:
	void Update(obs_data_t *settings);
	std::set<std::tuple<DWORD, std::string>> GetSessions();

	static std::tuple<std::string, std::string>
	MakeSessionOptionStrings(DWORD pid, const std::string &executable);

	static std::tuple<DWORD, std::string>
	ParseSessionOptionVal(const char *val);

	AudioCapture(obs_data_t *settings, obs_source_t *source);
	~AudioCapture();
};