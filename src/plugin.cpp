#include <obs-module.h>
#include "session-monitor.hpp"
#include "common.hpp"
#include "plugin-macros.generated.hpp"

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("win-capture-audio", "en-GB")

extern struct obs_source_info audio_capture_info;

bool obs_module_load(void)
{
	blog(LOG_INFO, "[win-capture-audio] Version %s (%s)", PLUGIN_VERSION, GIT_HASH);
	SessionMonitor::Create();

	obs_register_source(&audio_capture_info);
	return true;
}

void obs_module_unload()
{
	SessionMonitor::Destroy();
}
