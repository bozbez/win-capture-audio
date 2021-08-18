project(get-audio-offsets)

set(get-audio-offsets_SOURCES get-audio-offsets.c uuids.cpp)
add_executable(get-audio-offsets ${get-audio-offsets_SOURCES})
target_link_libraries(get-audio-offsets mmdevapi.lib)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_output_suffix "64")
else()
    set(_output_suffix "32")
endif()

set_target_properties(get-audio-offsets PROPERTIES
    OUTPUT_NAME "get-audio-offsets${_output_suffix}")

copy_helper_lib(get-audio-offsets)