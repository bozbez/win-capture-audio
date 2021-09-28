project(audio-capture-helper)

set(audio-capture-helper_SOURCES audio-capture-helper.cpp)
add_executable(audio-capture-helper ${audio-capture-helper_SOURCES})
target_link_libraries(audio-capture-helper libobs ksuser mmdevapi mfplat)
target_include_directories(audio-capture-helper PUBLIC ${CMAKE_SOURCE_DIR}/deps/wil/include)

set_target_properties(audio-capture-helper PROPERTIES
    OUTPUT_NAME "audio-capture-helper"
    CXX_STANDARD 20)

copy_helper_lib(audio-capture-helper)