cmake_minimum_required(VERSION 3.24)
project(test C)

set(CMAKE_C_STANDARD 11)

set(MAIN main.c)

add_executable(PROGRAM main.c micro-ecc/uECC.c nativeEndian.c nativeEndian.h)

target_link_libraries(PROGRAM m)

