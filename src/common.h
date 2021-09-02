#pragma once

#include <media-io/audio-io.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

#include <obs.h>

#define CALL(punk, method, ...) (punk)->lpVtbl->method((punk), __VA_ARGS__)
#define SAFE_RELEASE(punk)             \
	if ((punk) != NULL) {          \
		CALL((punk), Release); \
		(punk) = NULL;         \
	}

#define HELPER_DATA_SIZE (1024 * 1024)
#define HELPER_MAX_FRAMES 32

#define HELPER_DATA_NAME L"Local\\OBS_ACHelper_Data"

#define HELPER_WO_EVENT_SHUTDOWN_NAME L"Local\\OBS_ACHelper_WOEventShutdown"
#define HELPER_EVENT_DATA_NAME L"Local\\OBS_ACHelper_EventData"

#define NUM_HELPER_WO_EVENTS 1
#define NUM_HELPER_EVENTS 1
#define NUM_EVENTS 2

#define HELPER_WO_EVENTS_START 0
#define HELPER_WO_EVENTS_END (HELPER_WO_EVENTS_START + NUM_HELPER_WO_EVENTS)

#define HELPER_EVENTS_START HELPER_WO_EVENTS_END
#define HELPER_EVENTS_END (HELPER_EVENTS_START + NUM_HELPER_EVENTS)

#define EVENTS_START HELPER_EVENTS_END
#define EVENTS_END (EVENTS_START + NUM_EVENTS)

#define NUM_HELPER_EVENTS_TOTAL (NUM_HELPER_WO_EVENTS + NUM_HELPER_EVENTS)
#define NUM_EVENTS_TOTAL (NUM_HELPER_EVENTS_TOTAL + NUM_EVENTS)

enum event {
	HELPER_WO_EVENT_SHUTDOWN,

	HELPER_EVENT_DATA,

	EVENT_SHUTDOWN,
	EVENT_UPDATE,

	EVENT_PROCESS_TARGET,
	EVENT_PROCESS_HELPER,
};

static const wchar_t *event_names[NUM_EVENTS_TOTAL] = {
	HELPER_WO_EVENT_SHUTDOWN_NAME, HELPER_EVENT_DATA_NAME};

static inline void format_name_tag(wchar_t *buf, const wchar_t *name,
				   const char *tag)
{
	swprintf(buf, MAX_PATH, L"%s_%S", name, tag);
}

static inline void format_tag(char *buf, DWORD target_pid)
{
	sprintf(buf, "%lu_%lu_%lu", GetCurrentProcessId(), GetCurrentThreadId(),
		target_pid);
}

typedef struct audio_capture_helper_data {
	long lock;

	enum speaker_layout speakers;
	enum audio_format format;
	uint32_t samples_per_sec;

	uint32_t num_packets;

	uint32_t frames[HELPER_MAX_FRAMES];
	uint64_t timestamp[HELPER_MAX_FRAMES];

	size_t data_size[HELPER_MAX_FRAMES];
	uint8_t data[HELPER_MAX_FRAMES][HELPER_DATA_SIZE];
} audio_capture_helper_data_t;

static inline void safe_close_handle(HANDLE *handle)
{
	if (*handle != NULL) {
		CloseHandle(*handle);
		*handle = NULL;
	}
}