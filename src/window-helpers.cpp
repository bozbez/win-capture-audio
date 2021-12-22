#define PSAPI_VERSION 1

#include <dwmapi.h>
#include <psapi.h>

#include <util/base.h>
#include <util/platform.h>

#include "window-helpers.hpp"
#include "obfuscate.hpp"

extern void window_info_destroy(window_info_t *info)
{
	bfree(info->executable);
	bfree(info->cls);
	bfree(info->title);
}

extern bool window_info_cmp(window_info_t *info_a, window_info_t *info_b)
{

	if (info_a->title == NULL && info_b->title == NULL)
		return false;
	else if (info_a->title == NULL || info_b->title == NULL)
		return true;

	return strcmp(info_a->executable, info_b->executable) ||
	       strcmp(info_a->cls, info_b->cls) ||
	       strcmp(info_a->title, info_b->title);
}

static bool check_window_valid(HWND window, enum window_search_mode mode)
{
	DWORD styles, ex_styles;
	RECT rect;

	if (!IsWindowVisible(window) ||
	    (mode == EXCLUDE_MINIMIZED && IsIconic(window)))
		return false;

	GetClientRect(window, &rect);
	styles = (DWORD)GetWindowLongPtr(window, GWL_STYLE);
	ex_styles = (DWORD)GetWindowLongPtr(window, GWL_EXSTYLE);

	if (ex_styles & WS_EX_TOOLWINDOW)
		return false;
	if (styles & WS_CHILD)
		return false;
	if (mode == EXCLUDE_MINIMIZED && (rect.bottom == 0 || rect.right == 0))
		return false;

	return true;
}

static HWND next_window(HWND window, enum window_search_mode mode, HWND *parent,
			bool use_findwindowex)
{
	if (*parent) {
		window = *parent;
		*parent = NULL;
	}

	while (true) {
		if (use_findwindowex)
			window = FindWindowEx(GetDesktopWindow(), window, NULL,
					      NULL);
		else
			window = GetNextWindow(window, GW_HWNDNEXT);

		if (!window || check_window_valid(window, mode))
			break;
	}

	if (is_uwp_window(window)) {
		HWND child = get_uwp_actual_window(window);
		if (child) {
			*parent = window;
			return child;
		}
	}

	return window;
}

static HWND first_window(enum window_search_mode mode, HWND *parent,
			 bool *use_findwindowex)
{
	HWND window = FindWindowEx(GetDesktopWindow(), NULL, NULL, NULL);

	if (!window) {
		*use_findwindowex = false;
		window = GetWindow(GetDesktopWindow(), GW_CHILD);
	} else {
		*use_findwindowex = true;
	}

	*parent = NULL;

	if (!check_window_valid(window, mode)) {
		window = next_window(window, mode, parent, *use_findwindowex);

		if (!window && *use_findwindowex) {
			*use_findwindowex = false;

			window = GetWindow(GetDesktopWindow(), GW_CHILD);
			if (!check_window_valid(window, mode))
				window = next_window(window, mode, parent,
						     *use_findwindowex);
		}
	}

	if (is_uwp_window(window)) {
		HWND child = get_uwp_actual_window(window);
		if (child) {
			*parent = window;
			return child;
		}
	}

	return window;
}

static const char *generic_class_substrings[] = {
	"Chrome",
	NULL,
};

static const char *generic_classes[] = {
	"Windows.UI.Core.CoreWindow",
	NULL,
};

static bool is_generic_class(const char *current_class)
{
	const char **cls = generic_class_substrings;
	while (*cls) {
		if (astrstri(current_class, *cls) != NULL)
			return true;

		cls++;
	}

	cls = generic_classes;
	while (*cls) {
		if (astrcmpi(current_class, *cls) == 0)
			return true;

		cls++;
	}

	return false;
}

static int window_rating(HWND window, enum window_priority priority,
			 const window_info_t *info, bool generic_class)
{
	struct dstr cur_class = {0};
	struct dstr cur_title = {0};
	struct dstr cur_exe = {0};
	int val = INT_MAX;

	if (!get_window_exe(&cur_exe, window))
		return INT_MAX;

	get_window_title(&cur_title, window);
	get_window_class(&cur_class, window);

	bool exe_matches = dstr_cmpi(&cur_exe, info->executable) == 0;
	bool class_matches = dstr_cmpi(&cur_class, info->cls) == 0;
	int title_val = abs(dstr_cmpi(&cur_title, info->title));

	/* always match by name if class is generic */
	if (priority == WINDOW_PRIORITY_CLASS && generic_class) {
		val = title_val == 0 ? 0 : INT_MAX;

	} else if (priority == WINDOW_PRIORITY_CLASS) {
		val = class_matches ? title_val : INT_MAX;
		if (val != INT_MAX && !exe_matches)
			val += 0x1000;

	} else if (priority == WINDOW_PRIORITY_TITLE) {
		val = title_val == 0 ? 0 : INT_MAX;

	} else if (priority == WINDOW_PRIORITY_EXE) {
		val = exe_matches ? title_val : INT_MAX;
	}

	dstr_free(&cur_class);
	dstr_free(&cur_title);
	dstr_free(&cur_exe);

	return val;
}

extern HWND window_info_get_window(const window_info_t *info,
				   enum window_priority priority)
{
	if (strcmp(info->cls, "dwm") == 0) {
		wchar_t class_w[512];
		os_utf8_to_wcs(info->cls, 0, class_w, 512);
		return FindWindowW(class_w, NULL);
	}

	HWND parent;
	bool use_findwindowex = false;

	HWND window =
		first_window(INCLUDE_MINIMIZED, &parent, &use_findwindowex);
	HWND best_window = NULL;
	int best_rating = 0x7FFFFFFF;

	if (!info->cls)
		return NULL;

	bool generic_class = is_generic_class(info->cls);

	while (window) {
		int rating =
			window_rating(window, priority, info, generic_class);
		if (rating < best_rating) {
			best_rating = rating;
			best_window = window;
			if (rating == 0)
				break;
		}

		window = next_window(window, INCLUDE_MINIMIZED, &parent,
				     use_findwindowex);
	}

	return best_window;
}

static inline void encode_dstr(struct dstr *str)
{
	dstr_replace(str, "#", "#22");
	dstr_replace(str, ":", "#3A");
}

static inline char *decode_str(const char *src)
{
	struct dstr str = {0};
	dstr_copy(&str, src);
	dstr_replace(&str, "#3A", ":");
	dstr_replace(&str, "#22", "#");
	return str.array;
}

extern void build_window_strings(const char *str, window_info_t *info)
{
	char **strlist;

	info->cls = NULL;
	info->title = NULL;
	info->executable = NULL;

	if (!str) {
		return;
	}

	strlist = strlist_split(str, ':', true);

	if (strlist && strlist[0] && strlist[1] && strlist[2]) {
		info->title = decode_str(strlist[0]);
		info->cls = decode_str(strlist[1]);
		info->executable = decode_str(strlist[2]);
	}

	strlist_free(strlist);
}

static HMODULE kernel32(void)
{
	static HMODULE kernel32_handle = NULL;
	if (!kernel32_handle)
		kernel32_handle = GetModuleHandleA("kernel32");
	return kernel32_handle;
}

static inline HANDLE open_process(DWORD desired_access, bool inherit_handle,
				  DWORD process_id)
{
	typedef HANDLE(WINAPI * PFN_OpenProcess)(DWORD, BOOL, DWORD);
	static PFN_OpenProcess open_process_proc = NULL;
	if (!open_process_proc)
		open_process_proc = (PFN_OpenProcess)get_obfuscated_func(
			kernel32(), "B}caZyah`~q", 0x2D5BEBAF6DDULL);

	return open_process_proc(desired_access, inherit_handle, process_id);
}

bool get_window_exe(struct dstr *name, HWND window)
{
	wchar_t wname[MAX_PATH];
	struct dstr temp = {0};
	bool success = false;
	HANDLE process = NULL;
	char *slash;
	DWORD id;

	GetWindowThreadProcessId(window, &id);

	process = open_process(PROCESS_QUERY_LIMITED_INFORMATION, false, id);
	if (!process)
		goto fail;

	if (!GetProcessImageFileNameW(process, wname, MAX_PATH))
		goto fail;

	dstr_from_wcs(&temp, wname);
	slash = strrchr(temp.array, '\\');
	if (!slash)
		goto fail;

	dstr_copy(name, slash + 1);
	success = true;

fail:
	if (!success)
		dstr_copy(name, "unknown");

	dstr_free(&temp);
	CloseHandle(process);
	return true;
}

void get_window_title(struct dstr *name, HWND hwnd)
{
	wchar_t *temp;
	int len;

	len = GetWindowTextLengthW(hwnd);
	if (!len)
		return;

	temp = (wchar_t *)malloc(sizeof(wchar_t) * (len + 1));
	if (GetWindowTextW(hwnd, temp, len + 1))
		dstr_from_wcs(name, temp);
	free(temp);
}

void get_window_class(struct dstr *cls, HWND hwnd)
{
	wchar_t temp[256];

	temp[0] = 0;
	if (GetClassNameW(hwnd, temp, sizeof(temp) / sizeof(wchar_t)))
		dstr_from_wcs(cls, temp);
}

/* not capturable or internal windows, exact executable names */
static const char *internal_microsoft_exes_exact[] = {
	"startmenuexperiencehost.exe",
	"applicationframehost.exe",
	"peopleexperiencehost.exe",
	"shellexperiencehost.exe",
	"microsoft.notes.exe",
	"systemsettings.exe",
	"textinputhost.exe",
	"searchapp.exe",
	"searchui.exe",
	"lockapp.exe",
	"cortana.exe",
	"gamebar.exe",
	"tabtip.exe",
	"time.exe",
	NULL,
};

/* partial matches start from the beginning of the executable name */
static const char *internal_microsoft_exes_partial[] = {
	"windowsinternal",
	NULL,
};

static bool is_microsoft_internal_window_exe(const char *exe)
{
	if (!exe)
		return false;

	for (const char **vals = internal_microsoft_exes_exact; *vals; vals++) {
		if (astrcmpi(exe, *vals) == 0)
			return true;
	}

	for (const char **vals = internal_microsoft_exes_partial; *vals;
	     vals++) {
		if (astrcmpi_n(exe, *vals, strlen(*vals)) == 0)
			return true;
	}

	return false;
}

static const char *blacklisted_exes[] = {
	"explorer.exe",
	"steam.exe",
	"battle.net.exe",
	"galaxyclient.exe",
	"uplay.exe",
	"origin.exe",
	"devenv.exe",
	"taskmgr.exe",
	"systemsettings.exe",
	"applicationframehost.exe",
	"cmd.exe",
	"shellexperiencehost.exe",
	"winstore.app.exe",
	"searchui.exe",
	"lockapp.exe",
	"windowsinternal.composableshell.experiences.textinput.inputapp.exe",
	NULL,
};

bool is_blacklisted_exe(const char *exe)
{
	if (!exe)
		return false;

	for (const char **bl_exe = blacklisted_exes; *bl_exe != NULL;
	     ++bl_exe) {
		if (astrcmpi(exe, *bl_exe) == 0)
			return true;
	}

	return false;
}

static void add_window(obs_property_t *p, HWND hwnd, add_window_cb callback)
{
	struct dstr cls = {0};
	struct dstr title = {0};
	struct dstr exe = {0};
	struct dstr encoded = {0};
	struct dstr desc = {0};

	if (!get_window_exe(&exe, hwnd))
		return;
	if (is_microsoft_internal_window_exe(exe.array)) {
		dstr_free(&exe);
		return;
	}

	get_window_title(&title, hwnd);
	if (dstr_cmp(&exe, "explorer.exe") == 0 && dstr_is_empty(&title)) {
		dstr_free(&exe);
		dstr_free(&title);
		return;
	}

	get_window_class(&cls, hwnd);

	if (callback && !callback(title.array, cls.array, exe.array)) {
		dstr_free(&title);
		dstr_free(&cls);
		dstr_free(&exe);
		return;
	}

	dstr_printf(&desc, "[%s]: %s", exe.array, title.array);

	encode_dstr(&title);
	encode_dstr(&cls);
	encode_dstr(&exe);

	dstr_cat_dstr(&encoded, &title);
	dstr_cat(&encoded, ":");
	dstr_cat_dstr(&encoded, &cls);
	dstr_cat(&encoded, ":");
	dstr_cat_dstr(&encoded, &exe);

	obs_property_list_add_string(p, desc.array, encoded.array);

	dstr_free(&encoded);
	dstr_free(&desc);
	dstr_free(&cls);
	dstr_free(&title);
	dstr_free(&exe);
}

bool is_uwp_window(HWND hwnd)
{
	wchar_t name[256];

	name[0] = 0;
	if (!GetClassNameW(hwnd, name, sizeof(name) / sizeof(wchar_t)))
		return false;

	return wcscmp(name, L"ApplicationFrameWindow") == 0;
}

HWND get_uwp_actual_window(HWND parent)
{
	DWORD parent_id = 0;
	HWND child;

	GetWindowThreadProcessId(parent, &parent_id);
	child = FindWindowEx(parent, NULL, NULL, NULL);

	while (child) {
		DWORD child_id = 0;
		GetWindowThreadProcessId(child, &child_id);

		if (child_id != parent_id)
			return child;

		child = FindWindowEx(parent, child, NULL, NULL);
	}

	return NULL;
}

void fill_window_list(obs_property_t *p, enum window_search_mode mode,
		      add_window_cb callback)
{
	HWND parent;
	bool use_findwindowex = false;

	HWND window = first_window(mode, &parent, &use_findwindowex);

	while (window) {
		add_window(p, window, callback);
		window = next_window(window, mode, &parent, use_findwindowex);
	}
}