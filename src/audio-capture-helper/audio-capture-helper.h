#include <stdio.h>

#include <windows.h>
#include <audioclient.h>

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

	IAudioClient *client;
	IAudioCaptureClient *capture_client;

	WAVEFORMATEX *format;
	HANDLE event_data;

	HANDLE events[NUM_HELPER_EVENTS_TOTAL];

	HANDLE data_map;
	volatile audio_capture_helper_data_t *data;
} audio_capture_helper_context_t;
