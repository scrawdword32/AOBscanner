cmake_minimum_required(VERSION 3.10)

project(AOBscanner)

set(CMAKE_CXX_STANDARD 17)

include_directories(src)

set(SOURCES
    src/main.cpp
    src/scanner.cpp
    src/scanner.h
)

add_executable(aob_scanner ${SOURCES})