cmake_minimum_required(VERSION 3.20)
project(win-capture-audio VERSION 1.0.0)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
find_package(LibObs REQUIRED)

set(win-capture-audio_SOURCES
    src/plugin.c
    src/audio-capture.c
    src/obfuscate.c
    src/window-helpers.c
    src/inject-library.c)

add_library(win-capture-audio MODULE ${win-capture-audio_SOURCES})
target_link_libraries(win-capture-audio libobs dwmapi psapi ksuser)

add_subdirectory(src/get-audio-offsets)
add_subdirectory(src/audio-hook)
add_subdirectory(src/inject-helper)

add_custom_target(all-no-plugin)
add_dependencies(all-no-plugin get-audio-offsets audio-hook inject-helper)