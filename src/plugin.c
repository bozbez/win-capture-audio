#include <wchar.h>

#include <obs-module.h>
#include <util/config-file.h>
#include <util/dstr.h>

#include "util/base.h"
#include "util/pipe.h"

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("win-capture-audio", "en-GB")

extern struct obs_source_info audio_capture_info;

bool obs_module_load(void)
{
	obs_register_source(&audio_capture_info);
	return true;
}

void obs_module_unload() {}