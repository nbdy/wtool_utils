cmake_minimum_required(VERSION 3.17)
project(wtool_utils)

set(CMAKE_CXX_STANDARD 17)

add_executable(wtool_utils
        main.cpp)

include_directories(msgpack-c/include)
include_directories(ohlog)
include_directories(libsck)
include_directories(ext)
include_directories(libs)

target_link_libraries(wtool_utils pthread tins)

install(TARGETS wtool_utils
        RUNTIME DESTINATION bin)