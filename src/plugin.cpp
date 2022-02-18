#include <obs-module.h>
#include "common.hpp"
#include "plugin-macros.generated.h"

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("win-capture-audio", "en-GB")

extern struct obs_source_info audio_capture_info;

bool obs_module_load(void)
{
	blog(LOG_INFO, "[win-capture-audio] Version %s", PLUGIN_VERSION);
	obs_register_source(&audio_capture_info);
	return true;
}

void obs_module_unload() {}