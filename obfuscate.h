#pragma once

#include <windows.h>
#include <stdint.h>

/* this is a workaround to A/Vs going crazy whenever certain functions (such as
 * OpenProcess) are used */
extern void *get_obfuscated_func(HMODULE module, const char *str, uint64_t val);