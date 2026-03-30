cmake_minimum_required(VERSION 3.5)
project(multi_ssl_tun)

set(CMAKE_CXX_STANDARD 11)


# 添加include目录
include_directories(
        include
)


add_executable(multi_ssl_tun main.cpp
        fd_dispatcher.cc
        logger.cc
        main_thread.cc
        ssl_work_thread.cc
        channel.h)
