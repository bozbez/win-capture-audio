project(audio-capture-helper)

set(audio-capture-helper_SOURCES audio-capture-helper.c uuids.cpp)
add_executable(audio-capture-helper ${audio-capture-helper_SOURCES})
target_link_libraries(audio-capture-helper libobs ksuser mmdevapi)

set_target_properties(audio-capture-helper PROPERTIES
    OUTPUT_NAME "audio-capture-helper")

copy_helper_lib(audio-capture-helper)