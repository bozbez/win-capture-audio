#include <cstdint>
#include <cmath>
#include <cstdio>
#include <string>
#include <format>
#include <set>

#include <windows.h>
#include <stringapiset.h>
#include <processthreadsapi.h>
#include <mmreg.h>
#include <audiopolicy.h>
#include <audioclientactivationparams.h>

#include <obs.h>
#include <obs-module.h>
#include <obs-data.h>
#include <obs-properties.h>
#include <util/bmem.h>
#include <util/platform.h>
#include <winuser.h>

#include "wil/result_macros.h"
#include "audio-capture.hpp"

void AudioCapture::StartCapture(const std::set<DWORD> &new_pids)
{
	std::set<DWORD> current_pids;
	for (auto &[current_pid, _] : helpers)
		current_pids.insert(current_pid);

	for (auto current_pid : current_pids) {
		if (new_pids.contains(current_pid))
			continue;

		helpers.erase(current_pid);
	}

	for (auto new_pid : new_pids) {
		if (current_pids.contains(new_pid))
			continue;

		try {
			helpers.try_emplace(new_pid, source, new_pid);
		} catch (wil::ResultException e) {
			error("failed to create helper... update Windows?");
			error("%s", e.what());
		}
	}
}

void AudioCapture::StopCapture()
{
	try {
		debug("stopping capture");
		helpers.clear();
	} catch (wil::ResultException e) {
		error("failed to destroy helpers");
		error("%s", e.what());
	}
}

void AudioCapture::WorkerUpdate()
{
	auto config_lock = config_section.lock();
	auto config = this->config;
	config_lock.reset();

	if (config.mode == MODE_HOTKEY) {
		if (config.hotkey_window == NULL) {
			StopCapture();
			return;
		}

		DWORD pid;
		GetWindowThreadProcessId(config.hotkey_window, &pid);

		StartCapture({pid});
		return;
	}

	auto sessions_lock = sessions_section.lock();
	auto sessions = GetSessions();
	sessions_lock.reset();

	std::set<DWORD> pids;
	for (auto &[key, executable] : sessions) {
		if ((config.executable != executable) ^ config.exclude)
			continue;

		pids.insert(key.pid);
	}

	if (pids.size() > 0) {
		StartCapture(pids);
		return;
	}

	debug("target not found: %s", config.executable.value().c_str());
	StopCapture();
}

void AudioCapture::AddSession(const MSG &msg)
{
	auto key_ptr = reinterpret_cast<SessionKey *>(msg.wParam);
	auto key = SessionKey(std::move(*key_ptr));
	delete key_ptr;

	auto executable_ptr = reinterpret_cast<std::string *>(msg.lParam);
	auto executable = std::string(std::move(*executable_ptr));
	delete executable_ptr;

	debug("adding session: [%lu] %s", key.pid, executable.c_str());

	auto lock = sessions_section.lock();
	sessions.emplace(key, executable);
}

void AudioCapture::RemoveSession(const MSG &msg)
{
	auto key_ptr = reinterpret_cast<SessionKey *>(msg.wParam);
	auto key = SessionKey(std::move(*key_ptr));
	delete key_ptr;

	auto executable_ptr = reinterpret_cast<std::string *>(msg.lParam);
	auto executable = std::string(std::move(*executable_ptr));
	delete executable_ptr;

	debug("removing session: [%lu] %s", key.pid, executable.c_str());

	auto lock = sessions_section.lock();
	sessions.erase(key);
}

bool AudioCapture::Tick(const MSG &msg)
{
	bool shutdown = false;

	bool success;
	DWORD code;

	switch (msg.message) {
	case CaptureEvents::Shutdown:
		debug("shutting down");
		shutdown = true;

		break;

	case CaptureEvents::Update:
		WorkerUpdate();
		break;

	case CaptureEvents::SessionAdded:
		AddSession(msg);
		WorkerUpdate();
		break;

	case CaptureEvents::SessionExpired:
		RemoveSession(msg);
		WorkerUpdate();
		break;

	default:
		warn("unexpected event id, ignoring");
		break;
	}

	return shutdown;
}

void AudioCapture::Run()
{
	// Force message queue creation
	MSG msg;
	PeekMessageA(&msg, NULL, WM_USER, WM_USER, PM_NOREMOVE);

	worker_ready.SetEvent();

	bool shutdown = false;
	while (!shutdown) {
		if (!GetMessage(&msg, reinterpret_cast<HWND>(-1), WM_USER, 0)) {
			debug("shutting down");
			shutdown = true;
		}

		shutdown = Tick(msg);
	}

	StopCapture();
}

std::unordered_map<SessionKey, std::string> AudioCapture::GetSessions()
{
	auto lock = sessions_section.lock();
	return sessions;
};

void AudioCapture::Update(obs_data_t *settings)
{
	AudioCaptureConfig new_config = {
		.mode = (mode)obs_data_get_int(settings, SETTING_MODE),
		.exclude = obs_data_get_bool(settings, SETTING_EXCLUDE),
	};

	if (new_config.mode == MODE_SESSION) {
		const char *val =
			obs_data_get_string(settings, SETTING_SESSION);
		new_config.executable = std::string(val);
	}

	auto lock = config_section.lock();
	config = new_config;
	lock.reset();

	PostThreadMessageA(worker_tid, CaptureEvents::Update, NULL, NULL);
}

static void audio_capture_update(void *data, obs_data_t *settings)
{
	auto *ctx = static_cast<AudioCapture *>(data);
	ctx->Update(settings);
}

bool AudioCapture::IsUwpWindow(HWND window)
{
	wchar_t name[256] = {L'\0'};

	if (!GetClassNameW(window, name, sizeof(name) / sizeof(wchar_t)))
		return false;

	return wcscmp(name, L"ApplicationFrameWindow") == 0;
}

HWND AudioCapture::GetUwpActualWindow(HWND parent_window)
{
	DWORD parent_pid;
	HWND child_window;

	GetWindowThreadProcessId(parent_window, &parent_pid);
	child_window = FindWindowEx(parent_window, NULL, NULL, NULL);

	while (child_window != NULL) {
		DWORD child_pid;
		GetWindowThreadProcessId(child_window, &child_pid);

		if (child_pid != parent_pid)
			return child_window;

		child_window =
			FindWindowEx(parent_window, child_window, NULL, NULL);
	}

	return NULL;
}

void AudioCapture::HotkeyStart()
{
	auto lock = config_section.lock();
	auto config_copy = this->config;
	lock.reset();

	if (config_copy.mode != MODE_HOTKEY)
		return;

	auto window = GetForegroundWindow();
	if (AudioCapture::IsUwpWindow(window))
		window = AudioCapture::GetUwpActualWindow(window);

	lock = config_section.lock();
	config.hotkey_window = window;
	lock.reset();

	PostThreadMessageA(worker_tid, CaptureEvents::Update, NULL, NULL);
}

void AudioCapture::HotkeyStop()
{
	auto lock = config_section.lock();
	if (config.mode != MODE_HOTKEY)
		return;

	config.hotkey_window = NULL;
	lock.reset();

	PostThreadMessageA(worker_tid, CaptureEvents::Update, NULL, NULL);
}

static bool hotkey_start(void *data, obs_hotkey_pair_id id,
			 obs_hotkey_t *hotkey, bool pressed)
{
	if (!pressed)
		return false;

	auto *ctx = static_cast<AudioCapture *>(data);
	ctx->HotkeyStart();

	return true;
}

static bool hotkey_stop(void *data, obs_hotkey_pair_id id, obs_hotkey_t *hotkey,
			bool pressed)
{
	if (!pressed)
		return false;

	auto *ctx = static_cast<AudioCapture *>(data);
	ctx->HotkeyStop();

	return true;
}

AudioCapture::AudioCapture(obs_data_t *settings, obs_source_t *source)
	: source{source}
{
	Update(settings);

	worker_thread = std::thread(&AudioCapture::Run, this);

	worker_tid = GetThreadId(worker_thread.native_handle());
	session_monitor.emplace(worker_tid, CaptureEvents::SessionAdded,
				CaptureEvents::SessionExpired);

	hotkey_pair = obs_hotkey_pair_register_source(
		source, HOTKEY_START, TEXT_HOTKEY_START, HOTKEY_STOP,
		TEXT_HOTKEY_STOP, hotkey_start, hotkey_stop, this, this);
}

static void *audio_capture_create(obs_data_t *settings, obs_source_t *source)
{
	try {
		return new AudioCapture(settings, source);
	} catch (wil::ResultException e) {
		error("failed to create context: %s", e.what());
		return nullptr;
	}
}

AudioCapture::~AudioCapture()
{
	if (!worker_thread.joinable())
		return;

	worker_ready.wait();
	PostThreadMessageA(worker_tid, CaptureEvents::Shutdown, NULL, NULL);
	worker_thread.join();
}

static void audio_capture_destroy(void *data)
{
	auto *ctx = static_cast<AudioCapture *>(data);
	delete ctx;
}

static bool mode_callback(obs_properties_t *ps, obs_property_t *p,
			  obs_data_t *settings)
{
	int mode = obs_data_get_int(settings, SETTING_MODE);

	p = obs_properties_get(ps, SETTING_SESSION);
	obs_property_set_visible(p, mode == MODE_SESSION);

	return true;
}

std::tuple<std::string, std::string>
AudioCapture::MakeSessionOptionStrings(std::set<DWORD> pids,
				       const std::string &executable)
{
	auto pids_string = std::string();

	if (pids.size() > 0) {
		auto it = std::begin(pids);
		pids_string.append(std::format("{}", *it));

		++it;
		for (auto end = std::end(pids); it != end; ++it)
			pids_string.append(std::format(", {}", *it));
	} else {
		pids_string.append("*");
	}

	return {std::format("[{}] {}", pids_string, executable), executable};
}

static bool session_callback(obs_properties_t *ps, obs_property_t *p,
			     obs_data_t *settings)
{
	bool match = false;
	size_t i = 0;

	const char *cur_val = obs_data_get_string(settings, SETTING_SESSION);
	if (!cur_val)
		return false;

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
		auto [name, val] = AudioCapture::MakeSessionOptionStrings(
			{}, std::string(cur_val));

		obs_property_list_insert_string(p, 1, name.c_str(),
						val.c_str());
		obs_property_list_item_disable(p, 1, true);
		return true;
	}

	return false;
}

static obs_properties_t *audio_capture_properties(void *data)
{
	auto *ctx = static_cast<AudioCapture *>(data);

	obs_properties_t *ps = obs_properties_create();
	obs_property_t *p;

	// Mode setting (specific session or hotkey)
	p = obs_properties_add_list(ps, SETTING_MODE, TEXT_MODE,
				    OBS_COMBO_TYPE_LIST, OBS_COMBO_FORMAT_INT);

	obs_property_list_add_int(p, TEXT_MODE_SESSION, MODE_SESSION);
	obs_property_list_add_int(p, TEXT_MODE_HOTKEY, MODE_HOTKEY);

	obs_property_set_modified_callback(p, mode_callback);

	// Session setting
	p = obs_properties_add_list(ps, SETTING_SESSION, TEXT_SESSION,
				    OBS_COMBO_TYPE_LIST,
				    OBS_COMBO_FORMAT_STRING);

	obs_property_list_add_string(p, "", "");

	auto sessions = ctx->GetSessions();

	std::unordered_map<std::string, std::set<DWORD>> session_options;
	for (auto &[key, executable] : sessions)
		session_options[executable].insert(key.pid);

	for (auto &[executable, pids] : session_options) {
		auto [name, val] = AudioCapture::MakeSessionOptionStrings(
			pids, executable);
		obs_property_list_add_string(p, name.c_str(), val.c_str());
	}

	obs_property_set_modified_callback(p, session_callback);

	// Exclude setting
	p = obs_properties_add_bool(ps, SETTING_EXCLUDE, TEXT_EXCLUDE);

	return ps;
}

static void audio_capture_defaults(obs_data_t *settings)
{
	obs_data_set_default_int(settings, SETTING_MODE, MODE_SESSION);
	obs_data_set_default_string(settings, SETTING_SESSION, "");
	obs_data_set_default_bool(settings, SETTING_EXCLUDE, false);
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
