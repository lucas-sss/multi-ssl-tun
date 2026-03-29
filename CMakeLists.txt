cmake_minimum_required(VERSION 4.2)
project(multi_ssl_tun)

set(CMAKE_CXX_STANDARD 20)

add_executable(multi_ssl_tun main.cpp
        fd_dispatcher.cc
        logger.cc
        main_thread.cc)
