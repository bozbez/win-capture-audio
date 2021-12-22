#pragma once

#include <windows.h>

#include <obs.h>
#include <util/dstr.h>

enum window_priority {
	WINDOW_PRIORITY_CLASS,
	WINDOW_PRIORITY_TITLE,
	WINDOW_PRIORITY_EXE,
};

enum window_search_mode {
	INCLUDE_MINIMIZED,
	EXCLUDE_MINIMIZED,
};

struct window_info_t {
	char *executable;
	char *cls;
	char *title;
};

extern void window_info_destroy(window_info_t *info);
extern bool window_info_cmp(window_info_t *info_a, window_info_t *info_b);
extern HWND window_info_get_window(const window_info_t *info,
				   enum window_priority priority);

extern bool get_window_exe(struct dstr *name, HWND window);
extern void get_window_title(struct dstr *name, HWND hwnd);
extern void get_window_class(struct dstr *cls, HWND hwnd);

extern bool is_blacklisted_exe(const char *exe);

extern bool is_uwp_window(HWND hwnd);
extern HWND get_uwp_actual_window(HWND parent);

typedef bool (*add_window_cb)(const char *title, const char *cls,
			      const char *exe);

extern void fill_window_list(obs_property_t *p, enum window_search_mode mode,
			     add_window_cb callback);

extern void build_window_strings(const char *str, window_info_t *info);
