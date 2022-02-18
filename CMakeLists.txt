cmake_minimum_required(VERSION 3.20)
project(win-capture-audio VERSION 2.2.2)

set(PLUGIN_AUTHOR "bozbez")
set(RELEASE_DIR "${PROJECT_SOURCE_DIR}/release")

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(ARCH_NAME "64bit")
else()
    set(ARCH_NAME "32bit")
endif()

configure_file(
    installer/installer.iss.in
    ../installer/installer.generated.iss
)

execute_process(
    COMMAND git log -1 --format=%h
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR}
        OUTPUT_VARIABLE GIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
)

configure_file(
    src/plugin-macros.hpp.in
    ${CMAKE_SOURCE_DIR}/src/plugin-macros.generated.hpp
)

find_package(LibObs REQUIRED)

set(win-capture-audio_SOURCES
    src/plugin.cpp
    src/audio-capture.cpp
    src/audio-capture-helper.cpp
    src/session-monitor.cpp
    src/mixer.cpp)

add_library(win-capture-audio MODULE ${win-capture-audio_SOURCES})
target_link_libraries(win-capture-audio libobs dwmapi psapi ksuser mmdevapi mfplat)

set_property(TARGET win-capture-audio PROPERTY CXX_STANDARD 20)
target_include_directories(win-capture-audio PUBLIC ${CMAKE_SOURCE_DIR}/deps/wil/include)

add_custom_command(TARGET ${CMAKE_PROJECT_NAME} POST_BUILD
    COMMAND if $<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>==1 (
        "${CMAKE_COMMAND}" -E make_directory
            "${RELEASE_DIR}/data/obs-plugins/${CMAKE_PROJECT_NAME}"
            "${RELEASE_DIR}/obs-plugins/${ARCH_NAME}"
    )

    COMMAND if $<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>==1 (
        "${CMAKE_COMMAND}" -E copy_directory
            "${PROJECT_SOURCE_DIR}/data"
            "${RELEASE_DIR}/data/obs-plugins/${CMAKE_PROJECT_NAME}"
    )

    COMMAND if $<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>>==1 (
        "${CMAKE_COMMAND}" -E copy
            "$<TARGET_FILE:${CMAKE_PROJECT_NAME}>"
            "${RELEASE_DIR}/obs-plugins/${ARCH_NAME}"
    )

    COMMAND if $<CONFIG:RelWithDebInfo>==1 (
        "${CMAKE_COMMAND}" -E copy
            "$<TARGET_FILE_BASE_NAME:${CMAKE_PROJECT_NAME}>.pdb"
            "${RELEASE_DIR}/obs-plugins/${ARCH_NAME}"
    )

    VERBATIM
)