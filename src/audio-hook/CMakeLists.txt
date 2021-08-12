project(audio-hook)

find_package(Detours REQUIRED)

set(audio-hook_SOURCES
    audio-hook.c
    ../obfuscate.c)

add_library(audio-hook MODULE ${audio-hook_SOURCES})

target_include_directories(audio-hook PUBLIC ${DETOURS_INCLUDE_DIR})
target_link_libraries(audio-hook ${DETOURS_LIBRARIES} psapi)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
	set(_output_suffix "64")
else()
	set(_output_suffix "32")
endif()

set_target_properties(audio-hook
	PROPERTIES OUTPUT_NAME "audio-hook${_output_suffix}")