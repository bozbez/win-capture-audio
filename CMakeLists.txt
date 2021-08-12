cmake_minimum_required(VERSION 3.20)
project(win-capture-audio)

find_package(LibObs REQUIRED)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

set(win-capture-audio_SOURCES
    plugin.c
    audio-capture.c
    obfuscate.c
    window-helpers.c
    inject-library.c)

add_library(win-capture-audio MODULE ${win-capture-audio_SOURCES})
target_link_libraries(win-capture-audio libobs dwmapi psapi ksuser)

add_subdirectory(get-audio-offsets)
add_subdirectory(audio-hook)
add_subdirectory(inject-helper)

add_custom_target(all-no-plugin)
add_dependencies(all-no-plugin get-audio-offsets audio-hook inject-helper)