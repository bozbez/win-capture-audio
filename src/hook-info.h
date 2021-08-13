#pragma once

#include <windows.h>
#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>

#include <Audioclient.h>


/* clang-format off */

#define HOOK_DATA_SIZE               (1024 * 1024 * 1024)

#define HOOK_DATA_NAME               L"Local\\OBS_ACHook_Data"
#define HOOK_METADATA_NAME           L"Local\\OBS_ACHook_Metadata"

#define HOOK_WO_EVENT_PING_NAME      L"Local\\OBS_ACHook_WOEventPing"
#define HOOK_WO_EVENT_START_NAME     L"Local\\OBS_ACHook_WOEventStart"
#define HOOK_WO_EVENT_STOP_NAME      L"Local\\OBS_ACHook_WOEventStop"
#define HOOK_WO_EVENT_SHUTDOWN_NAME  L"Local\\OBS_ACHook_WOEventShutdown"

#define HOOK_EVENT_READY_NAME        L"Local\\OBS_ACHook_EventReady"
#define HOOK_EVENT_ACTIVE_NAME       L"Local\\OBS_ACHook_EventActive"
#define HOOK_EVENT_DATA_NAME         L"Local\\OBS_ACHook_EventData"

#define NUM_HOOK_WO_EVENTS           4
#define NUM_HOOK_EVENTS              3
#define NUM_EVENTS                   2

#define HOOK_WO_EVENTS_START         0
#define HOOK_WO_EVENTS_END           (HOOK_WO_EVENTS_START + NUM_HOOK_WO_EVENTS)

#define HOOK_EVENTS_START            HOOK_WO_EVENTS_END
#define HOOK_EVENTS_END              (HOOK_EVENTS_START + NUM_HOOK_EVENTS)

#define EVENTS_START                 HOOK_EVENTS_END
#define EVENTS_END                   (EVENTS_START + NUM_EVENTS)

#define NUM_HOOK_EVENTS_TOTAL        (NUM_HOOK_WO_EVENTS + NUM_HOOK_EVENTS)
#define NUM_EVENTS_TOTAL             (NUM_HOOK_EVENTS_TOTAL + NUM_EVENTS)

/* clang-format on */

enum event {
	HOOK_WO_EVENT_PING,
	HOOK_WO_EVENT_START,
	HOOK_WO_EVENT_STOP,
	HOOK_WO_EVENT_SHUTDOWN,

	HOOK_EVENT_READY,
	HOOK_EVENT_ACTIVE,
	HOOK_EVENT_DATA,

	EVENT_SHUTDOWN,
	EVENT_REHOOK,
};

typedef struct event_info {
	wchar_t *name;
	bool reset;
} event_info_t;

static event_info_t event_info[NUM_EVENTS_TOTAL] = {
	{HOOK_WO_EVENT_PING_NAME, FALSE},
	{HOOK_WO_EVENT_START_NAME, FALSE},
	{HOOK_WO_EVENT_STOP_NAME, FALSE},
	{HOOK_WO_EVENT_SHUTDOWN_NAME, FALSE},

	{HOOK_EVENT_READY_NAME, FALSE},
	{HOOK_EVENT_ACTIVE_NAME, FALSE},
	{HOOK_EVENT_DATA_NAME, FALSE},

	{NULL, FALSE},
	{NULL, FALSE},
};

typedef struct audio_hook_offsets {
	struct {
		uint32_t client_vtbl;
		uint32_t render_client_vtbl;

		uint32_t m_render_client_client;
		uint32_t m_render_client_format;
	} wasapi;
} audio_hook_offsets_t;

typedef struct audio_hook_metadata {
	long initialized;

	audio_hook_offsets_t offsets32;
	audio_hook_offsets_t offsets64;
} audio_hook_metadata_t;

typedef struct audio_hook_data {
	long lock;

	WAVEFORMATEXTENSIBLE format;
	
	uint64_t timestamp;
	uint32_t frames;

	uint8_t data[HOOK_DATA_SIZE];
} audio_hook_data_t;

static inline void format_name_pid(wchar_t *buf, const wchar_t *name, DWORD pid)
{
	swprintf(buf, MAX_PATH, L"%s%lu", name, pid);
}

static inline void format_name(wchar_t *buf, const wchar_t *name)
{
	format_name_pid(buf, name, GetCurrentProcessId());
}
