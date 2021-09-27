#include <stdio.h>

#include <windows.h>
#include <audioclient.h>

#include <wil/com.h>

#include "../common.h"

#define do_log(format, ...) fprintf(stderr, format, ##__VA_ARGS__)

#define error(format, ...) \
	do_log("error: (%s): " format "\n", __func__, ##__VA_ARGS__)
#define warn(format, ...) \
	do_log("warn: (%s): " format "\n", __func__, ##__VA_ARGS__)
#define info(format, ...) \
	do_log("info: (%s): " format "\n", __func__, ##__VA_ARGS__)
#define debug(format, ...) \
	do_log("debug: (%s): " format "\n", __func__, ##__VA_ARGS__)

typedef struct capture_options {
	DWORD pid;
	bool include_tree;

	char *tag;
} capture_options_t;

typedef struct audio_capture_helper_context {
	capture_options_t options;

	wil::com_ptr<IAudioClient> client;
	wil::com_ptr<IAudioCaptureClient> capture_client;

	wil::unique_cotaskmem_ptr<WAVEFORMATEX> format;
	
	wil::unique_event event_data;
	wil::unique_event events[NUM_HELPER_EVENTS_TOTAL];

	wil::unique_handle data_map;
	wil::unique_mapview_ptr<audio_capture_helper_data_t> data;
} audio_capture_helper_context_t;
