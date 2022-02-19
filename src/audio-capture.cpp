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
#include "audio-capture-helper-manager.hpp"

AudioCaptureHelperManager helper_manager;

void AudioCapture::StartCapture(const std::set<DWORD> &new_pids)
{
	for (auto pid : pids) {
		if (new_pids.contains(pid))
			continue;

		helper_manager.UnRegisterMixer(pid, &mixer.value());
	}

	for (auto new_pid : new_pids) {
		if (pids.contains(new_pid))
			continue;

		helper_manager.RegisterMixer(new_pid, &mixer.value());
	}

	pids = new_pids;
}

void AudioCapture::StopCapture()
{
	for (auto pid : pids)
		helper_manager.UnRegisterMixer(pid, &mixer.value());

	pids.clear();
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
		if ((!config.executables.contains(executable)) ^ config.exclude)
			continue;

		pids.insert(key.pid);
	}

	if (pids.size() > 0) {
		StartCapture(pids);
		return;
	}

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

	if (new_config.mode == MODE_SESSION)
		new_config.executables = GetExecutables(settings);

	auto lock = config_section.lock();
	config = std::move(new_config);
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

		child_window = FindWindowEx(parent_window, child_window, NULL, NULL);
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

static bool hotkey_start(void *data, obs_hotkey_pair_id id, obs_hotkey_t *hotkey, bool pressed)
{
	if (!pressed)
		return false;

	auto *ctx = static_cast<AudioCapture *>(data);
	ctx->HotkeyStart();

	return true;
}

static bool hotkey_stop(void *data, obs_hotkey_pair_id id, obs_hotkey_t *hotkey, bool pressed)
{
	if (!pressed)
		return false;

	auto *ctx = static_cast<AudioCapture *>(data);
	ctx->HotkeyStop();

	return true;
}

AudioCapture::AudioCapture(obs_data_t *settings, obs_source_t *source) : source{source}
{
	Update(settings);

	mixer.emplace(source, helper_manager.GetFormat());

	worker_thread = std::thread(&AudioCapture::Run, this);

	worker_tid = GetThreadId(worker_thread.native_handle());
	session_monitor.emplace(worker_tid, CaptureEvents::SessionAdded,
				CaptureEvents::SessionExpired);

	hotkey_pair = obs_hotkey_pair_register_source(source, HOTKEY_START, TEXT_HOTKEY_START,
						      HOTKEY_STOP, TEXT_HOTKEY_STOP, hotkey_start,
						      hotkey_stop, this, this);
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

static bool mode_callback(obs_properties_t *ps, obs_property_t *p, obs_data_t *settings)
{
	int mode = obs_data_get_int(settings, SETTING_MODE);

	p = obs_properties_get(ps, SETTING_EXECUTABLE_LIST);
	obs_property_set_visible(p, mode == MODE_SESSION);

	p = obs_properties_get(ps, SETTING_ACTIVE_SESSION_GROUP);
	obs_property_set_visible(p, mode == MODE_SESSION);

	p = obs_properties_get(ps, SETTING_EXCLUDE);
	obs_property_set_visible(p, mode == MODE_SESSION);

	return true;
}

std::tuple<std::string, std::string>
AudioCapture::MakeSessionOptionStrings(std::set<DWORD> pids, const std::string &executable)
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

static bool executable_list_callback(void *data, obs_properties_t *ps, obs_property_t *p,
				     obs_data_t *settings)
{
	auto *ctx = static_cast<AudioCapture *>(data);

	auto *active_session_list = obs_properties_get(ps, SETTING_ACTIVE_SESSION_LIST);
	auto *active_session_add = obs_properties_get(ps, SETTING_ACTIVE_SESSION_ADD);

	obs_property_list_clear(active_session_list);
	ctx->FillActiveSessionList(active_session_list, active_session_add);

	return true;
}

static bool session_add_callback(obs_properties_t *ps, obs_property_t *p, void *data)
{
	auto *ctx = static_cast<AudioCapture *>(data);
	auto *source = ctx->GetSource();

	auto *settings = obs_source_get_settings(source);
	auto *executable_list_array = obs_data_get_array(settings, SETTING_EXECUTABLE_LIST);

	if (obs_data_array_count(executable_list_array) == 0) {
		obs_data_array_release(executable_list_array);

		executable_list_array = obs_data_array_create();
		obs_data_set_array(settings, SETTING_EXECUTABLE_LIST, executable_list_array);
	}

	const char *executable = obs_data_get_string(settings, SETTING_ACTIVE_SESSION_LIST);
	auto *executable_obj = obs_data_create();

	obs_data_set_bool(executable_obj, "hidden", false);
	obs_data_set_bool(executable_obj, "selected", false);
	obs_data_set_string(executable_obj, "value", executable);

	obs_data_array_push_back(executable_list_array, executable_obj);

	auto *active_session_list = obs_properties_get(ps, SETTING_ACTIVE_SESSION_LIST);
	auto *active_session_add = obs_properties_get(ps, SETTING_ACTIVE_SESSION_ADD);

	obs_property_list_clear(active_session_list);
	ctx->FillActiveSessionList(active_session_list, active_session_add);

	obs_data_release(executable_obj);
	obs_data_array_release(executable_list_array);
	obs_data_release(settings);

	return true;
}

std::set<std::string> AudioCapture::GetExecutables(obs_data_t *settings)
{
	auto *executable_list_array = obs_data_get_array(settings, SETTING_EXECUTABLE_LIST);
	auto count = obs_data_array_count(executable_list_array);

	std::set<std::string> executables;

	for (std::size_t i = 0; i < count; ++i) {
		auto *item = obs_data_array_item(executable_list_array, i);
		auto *executable = obs_data_get_string(item, "value");

		executables.insert(std::string(executable));
	}

	obs_data_array_release(executable_list_array);
	return executables;
}

void AudioCapture::FillActiveSessionList(obs_property_t *session_list, obs_property_t *session_add)
{
	auto *settings = obs_source_get_settings(GetSource());

	auto sessions = GetSessions();
	auto executables = GetExecutables(settings);

	std::unordered_map<std::string, std::set<DWORD>> session_options;
	for (auto &[key, executable] : sessions) {
		if (executables.contains(executable))
			continue;

		session_options[executable].insert(key.pid);
	}

	for (auto &[executable, pids] : session_options) {
		auto [name, val] = AudioCapture::MakeSessionOptionStrings(pids, executable);
		obs_property_list_add_string(session_list, name.c_str(), val.c_str());
	}

	obs_property_set_enabled(session_add, session_options.size() != 0);
	obs_property_set_enabled(session_list, session_options.size() != 0);

	obs_data_release(settings);
}

static obs_properties_t *audio_capture_properties(void *data)
{
	auto *ctx = static_cast<AudioCapture *>(data);

	obs_properties_t *ps = obs_properties_create();

	// Mode setting (specific session or hotkey)
	auto *mode = obs_properties_add_list(ps, SETTING_MODE, TEXT_MODE, OBS_COMBO_TYPE_LIST,
					     OBS_COMBO_FORMAT_INT);

	obs_property_list_add_int(mode, TEXT_MODE_SESSION, MODE_SESSION);
	obs_property_list_add_int(mode, TEXT_MODE_HOTKEY, MODE_HOTKEY);

	obs_property_set_modified_callback(mode, mode_callback);

	// Executable list setting
	auto *executable_list =
		obs_properties_add_editable_list(ps, SETTING_EXECUTABLE_LIST, TEXT_EXECUTABLE_LIST,
						 OBS_EDITABLE_LIST_TYPE_STRINGS, NULL, NULL);

	obs_property_set_modified_callback2(executable_list, executable_list_callback, ctx);

	// Exclude setting
	obs_properties_add_bool(ps, SETTING_EXCLUDE, TEXT_EXCLUDE);

	// Active session group
	obs_properties_t *active_session_group = obs_properties_create();

	// Active session list
	auto *active_session_list = obs_properties_add_list(
		active_session_group, SETTING_ACTIVE_SESSION_LIST, TEXT_ACTIVE_SESSION_LIST,
		OBS_COMBO_TYPE_LIST, OBS_COMBO_FORMAT_STRING);

	// Add session button
	auto *active_session_add =
		obs_properties_add_button(active_session_group, SETTING_ACTIVE_SESSION_ADD,
					  TEXT_ACTIVE_SESSION_ADD, session_add_callback);

	ctx->FillActiveSessionList(active_session_list, active_session_add);

	// Active session group
	obs_properties_add_group(ps, SETTING_ACTIVE_SESSION_GROUP, TEXT_ACTIVE_SESSION_GROUP,
				 OBS_GROUP_NORMAL, active_session_group);

	return ps;
}

static void audio_capture_defaults(obs_data_t *settings)
{
	obs_data_set_default_int(settings, SETTING_MODE, MODE_SESSION);

	auto *executable_list = obs_data_array_create();
	obs_data_set_default_array(settings, SETTING_EXECUTABLE_LIST, executable_list);
	obs_data_array_release(executable_list);

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
