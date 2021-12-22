#pragma once

#include <util/platform.h>
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

#define NUM_EVENTS 2

#define EVENTS_START 0
#define EVENTS_END (EVENTS_START + NUM_EVENTS)

#define do_log(level, format, ...) \
	do_log_source(level, "(%s) " format, __func__, ##__VA_ARGS__)

inline static void do_log_source(int level, const char *format, ...)
{
	va_list args;
	va_start(args, format);

	const char *name = "unknown";
	int len = strlen(name);

	const char *format_source = len <= 8 ? "[audio-capture: '%s'] %s"
					     : "[audio-capture: '%.8s...'] %s";

	int len_full = strlen(format_source) + 12 + strlen(format);
	char *format_full = (char *)bzalloc(len_full);

	snprintf(format_full, len_full, format_source, name, format);
	blogva(level, format_full, args);

	bfree(format_full);
	va_end(args);
}

#define error(format, ...) do_log(LOG_ERROR, format, ##__VA_ARGS__)
#define warn(format, ...) do_log(LOG_WARNING, format, ##__VA_ARGS__)
#define info(format, ...) do_log(LOG_INFO, format, ##__VA_ARGS__)
#define debug(format, ...) do_log(LOG_INFO, format, ##__VA_ARGS__)

enum event {
	EVENT_SHUTDOWN,
	EVENT_UPDATE,

	EVENT_PROCESS_TARGET,
};

static inline void safe_close_handle(HANDLE *handle)
{
	if (*handle != NULL) {
		CloseHandle(*handle);
		*handle = NULL;
	}
}