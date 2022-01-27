#include <stdint.h>
#include <math.h>
#include <cstdio>
#include <string>
#include <format>

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

void AudioCapture::StartCapture(DWORD pid, bool exclude)
{
	try {
		if (helper.has_value() && helper.value().GetPid() == pid &&
		    helper.value().GetIncludeTree() == !exclude)
			return;

		debug("starting capture on: %lu", pid);
		helper.emplace(source, pid, !exclude);
	} catch (wil::ResultException e) {
		error("failed to create helper... update Windows?");
		error("%s", e.what());
	}
}

void AudioCapture::StopCapture()
{
	try {
		debug("stopping capture");
		helper.reset();
	} catch (wil::ResultException e) {
		error("failed to destroy helper");
		error("%s", e.what());
	}
}

void AudioCapture::WorkerUpdate()
{
	auto config_lock = config_section.lock();
	auto config = this->config;
	config_lock.reset();

	if (config.mode == MODE_HOTKEY)
		return;

	auto sessions_lock = sessions_section.lock();
	auto sessions = this->sessions;
	sessions_lock.reset();

	auto [target_pid, target_executable] = config.session.value();

	// Search for a match with both PID and executable name first
	for (auto &[key, executable] : sessions) {
		if (target_pid != key.pid ||
		    target_executable != target_executable)
			continue;

		StartCapture(key.pid, config.exclude_process_tree);
		return;
	}

	// Then try matching just the executable name
	for (auto &[key, executable] : sessions) {
		if (target_executable != executable)
			continue;

		StartCapture(key.pid, config.exclude_process_tree);
		return;
	}

	debug("target not found: [%lu] %s", target_pid,
	      target_executable.c_str());
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
		.exclude_process_tree = obs_data_get_bool(
			settings, SETTING_EXCLUDE_PROCESS_TREE),
	};

	if (new_config.mode == MODE_SESSION) {
		const char *val =
			obs_data_get_string(settings, SETTING_SESSION);
		new_config.session = AudioCapture::ParseSessionOptionVal(val);
	}

	auto lock = config_section.lock();

	auto need_update = new_config != config;
	config = new_config;

	lock.reset();

	if (need_update)
		PostThreadMessageA(worker_tid, CaptureEvents::Update, NULL,
				   NULL);
}

static void audio_capture_update(void *data, obs_data_t *settings)
{
	auto *ctx = static_cast<AudioCapture *>(data);
	ctx->Update(settings);
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

AudioCapture::AudioCapture(obs_data_t *settings, obs_source_t *source)
	: source{source}
{
	Update(settings);
	worker_thread = std::thread(&AudioCapture::Run, this);

	worker_tid = GetThreadId(worker_thread.native_handle());
	session_monitor.emplace(worker_tid, CaptureEvents::SessionAdded,
				CaptureEvents::SessionExpired);
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

static bool mode_callback(obs_properties_t *ps, obs_property_t *p,
			  obs_data_t *settings)
{
	int mode = obs_data_get_int(settings, SETTING_MODE);

	p = obs_properties_get(ps, SETTING_SESSION);
	obs_property_set_visible(p, mode == MODE_SESSION);

	return true;
}

std::tuple<std::string, std::string>
AudioCapture::MakeSessionOptionStrings(DWORD pid, const std::string &executable)
{
	std::string name = std::format("[{}] {}", pid, executable);
	std::string val = std::format("{} {}", pid, executable);

	return {name, val};
}

std::tuple<DWORD, std::string>
AudioCapture::ParseSessionOptionVal(const char *val)
{
	auto val_str = std::string(val);
	auto pos = val_str.find(" ");

	auto dword_str = val_str.substr(0, pos);
	auto executable = val_str.substr(pos + 1);

	auto pid = std::strtoul(dword_str.c_str(), NULL, 10);

	return {pid, executable};
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
		auto [pid, executable] =
			AudioCapture::ParseSessionOptionVal(cur_val);

		auto [name, val] =
			AudioCapture::MakeSessionOptionStrings(pid, executable);

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

	obs_property_list_add_int(p, TEXT_MODE_WINDOW, MODE_SESSION);
	obs_property_list_add_int(p, TEXT_MODE_HOTKEY, MODE_HOTKEY);

	obs_property_set_modified_callback(p, mode_callback);

	// Session setting
	p = obs_properties_add_list(ps, SETTING_SESSION, TEXT_SESSION,
				    OBS_COMBO_TYPE_LIST,
				    OBS_COMBO_FORMAT_STRING);

	obs_property_list_add_string(p, "", "");

	auto sessions = ctx->GetSessions();
	for (auto &[key, executable] : sessions) {
		auto [name, val] = AudioCapture::MakeSessionOptionStrings(
			key.pid, executable);
		obs_property_list_add_string(p, name.c_str(), val.c_str());
	}

	obs_property_set_modified_callback(p, session_callback);

	// Exclude process tree setting
	p = obs_properties_add_bool(ps, SETTING_EXCLUDE_PROCESS_TREE,
				    TEXT_EXCLUDE_PROCESS_TREE);

	return ps;
}

static void audio_capture_defaults(obs_data_t *settings)
{
	obs_data_set_default_int(settings, SETTING_MODE, MODE_SESSION);
	obs_data_set_default_string(settings, SETTING_SESSION, "");
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
