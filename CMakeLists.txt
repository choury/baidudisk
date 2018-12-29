cmake_minimum_required(VERSION 2.8)
project(baidudisk)
include_directories(fmdisk/include)

find_package(OpenSSL 1.0.2 REQUIRED)
include_directories(${OPENSSL_INCLUDE_DIR})

#set(CMAKE_C_FLAGS "-Wall -ggdb -O0 -fsanitize=address -fsanitize=undefined")
#set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -ggdb -O0 -fsanitize=address -fsanitize=undefined")

set(CMAKE_C_FLAGS "-Wall -ggdb -O0")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -ggdb -O0")


#set(CMAKE_C_FLAGS "-Wall -O2 -DNDEBUG -ggdb")
#set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -O2 -DNDEBUG -ggdb")

add_subdirectory(fmdisk)
add_executable(baidudisk baiduapi.cpp net.c main.c)
target_link_libraries(baidudisk fmdisk curl ssl crypto)

add_executable(baiducheck baiduapi.cpp net.c)
target_link_libraries(baiducheck fmcheck curl ssl crypto)
