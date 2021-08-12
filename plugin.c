#include <wchar.h>

#include <obs-module.h>
#include <util/config-file.h>
#include <util/dstr.h>

#include "hook-info.h"
#include "util/base.h"
#include "util/pipe.h"

OBS_DECLARE_MODULE()
OBS_MODULE_USE_DEFAULT_LOCALE("win-capture-audio", "en-GB")

extern struct obs_source_info audio_capture_info;

HANDLE init_hook_metadata_thread;

HANDLE hook_metadata_map;
volatile audio_hook_metadata_t *hook_metadata;

static inline bool is_64bit_windows(void)
{
#ifdef _WIN64
	return true;
#else
	BOOL x86 = false;
	bool success = !!IsWow64Process(GetCurrentProcess(), &x86);
	return success && !!x86;
#endif
}

static char *read_cmd_output(char *cmd)
{
	os_process_pipe_t *pipe = os_process_pipe_create(cmd, "r");

	if (!pipe)
		return NULL;

	struct dstr output = {0};

	while (true) {
		char data[2048];
		size_t len = os_process_pipe_read(pipe, (uint8_t *)data,
						  sizeof(data));
		if (len == 0)
			break;

		dstr_ncat(&output, data, len);
	}

	if (dstr_is_empty(&output))
		return NULL;

	return output.array;
}

static bool load_offsets_from_string(volatile audio_hook_offsets_t *offsets,
				     const char *str)
{
	config_t *config;

	if (config_open_string(&config, str) != CONFIG_SUCCESS)
		return false;

	offsets->wasapi.client_vtbl =
		(uint32_t)config_get_uint(config, "wasapi", "client_vtbl");
	offsets->wasapi.render_client_vtbl = (uint32_t)config_get_uint(
		config, "wasapi", "render_client_vtbl");
	offsets->wasapi.m_render_client_client = (uint32_t)config_get_uint(
		config, "wasapi", "m_render_client_client");
	offsets->wasapi.m_render_client_format = (uint32_t)config_get_uint(
		config, "wasapi", "m_render_client_format");

	config_close(config);

	return !(offsets->wasapi.client_vtbl == 0 ||
		 offsets->wasapi.render_client_vtbl == 0 ||
		 offsets->wasapi.m_render_client_client == 0 ||
		 offsets->wasapi.m_render_client_format == 0);
}

static bool load_offsets_from_exe(volatile audio_hook_offsets_t *offsets,
				  const char *exe)
{
	char *offsets_cmd = obs_module_file(exe);
	char *offsets_str = read_cmd_output(offsets_cmd);

	bool success = false;

	if (offsets_str == NULL) {
		blog(LOG_ERROR, "[audio-capture] failed run %s", exe);
		goto exit;
	}

	if (!load_offsets_from_string(offsets, offsets_str)) {
		blog(LOG_ERROR,
		     "[audio-capture] failed to load audio offsets from %s",
		     exe);
		goto exit;
	}

	success = true;

exit:
	bfree(offsets_cmd);
	bfree(offsets_str);

	return success;
}

static DWORD WINAPI init_hook_metadata(LPVOID param)
{
	UNUSED_PARAMETER(param);


	if (!load_offsets_from_exe(&hook_metadata->offsets32,
				   "get-audio-offsets32.exe")) {
		blog(LOG_ERROR,
		     "[audio-capture] failed to load 32-bit audio offsets");
		return 1;
	}

	if (is_64bit_windows() &&
	    !load_offsets_from_exe(&hook_metadata->offsets64,
				   "get-audio-offsets64.exe")) {
		blog(LOG_ERROR,
		     "[audio-capture] failed to load 64-bit audio offsets");
		return 1;
	}


	hook_metadata->initialized = true;
	return 0;
}

bool obs_module_load(void)
{
	hook_metadata_map = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL,
					       PAGE_READWRITE, 0,
					       sizeof(audio_hook_metadata_t),
					       HOOK_METADATA_NAME);

	if (hook_metadata_map == NULL) {
		blog(LOG_ERROR,
		     "[audio-capture] failed to create hook metadata map");
		return false;
	}

	hook_metadata = MapViewOfFile(hook_metadata_map, FILE_MAP_ALL_ACCESS, 0,
				      0, sizeof(audio_hook_metadata_t));

	if (hook_metadata == NULL) {
		blog(LOG_ERROR,
		     "[audio-capture] failed to create hook metadata view");

		CloseHandle(hook_metadata_map);
		return false;
	}

	init_hook_metadata_thread =
		CreateThread(NULL, 0, init_hook_metadata, NULL, 0, NULL);

	if (init_hook_metadata_thread == NULL) {
		blog(LOG_ERROR,
		     "[audio-capture] failed to create hook metadata "
		     "init thread");

		UnmapViewOfFile((void *)hook_metadata);
		CloseHandle(hook_metadata_map);
		return false;
	}

	obs_register_source(&audio_capture_info);
	return true;
}

void obs_module_unload()
{
	if (init_hook_metadata_thread == NULL)
		return;

	WaitForSingleObject(init_hook_metadata_thread, INFINITE);

	UnmapViewOfFile((void *)hook_metadata);
	CloseHandle(hook_metadata_map);
}