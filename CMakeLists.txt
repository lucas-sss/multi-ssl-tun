cmake_minimum_required(VERSION 2.8)
project(multi_ssl_tun)

# CMake 2.8 does not reliably honor CMAKE_CXX_STANDARD.
# Force GCC/Clang to compile in C++11 mode for old toolchains.
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=gnu++11 -pthread")


# 添加include目录
include_directories(
        ${PROJECT_SOURCE_DIR}/include
)
link_directories("/opt/tongsuo/lib64")


add_executable(multi_ssl_tun main.cpp
        fd_dispatcher.cc
        logger.cc
        main_thread.cc
        ssl_work_thread.cc
        channel.h
        protocol.cc)

target_link_libraries(multi_ssl_tun ssl crypto pthread)
