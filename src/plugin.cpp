#include <obs-module.h>
#include "audio-capture-helper.hpp"
#include "common.hpp"
#include "plugin-macros.generated.hpp"

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("win-capture-audio", "en-GB")

extern struct obs_source_info audio_capture_info;
extern bool system_supported;

bool obs_module_load(void)
{
	blog(LOG_INFO, "[win-capture-audio] Version %s (%s)", PLUGIN_VERSION, GIT_HASH);
	system_supported = AudioCaptureHelper::TestPluginAvailable();
	obs_register_source(&audio_capture_info);
	return true;
}

void obs_module_unload() {}