cmake_minimum_required(VERSION 2.8)
project(baidudisk)
include_directories(fmdisk/include)

#set(CMAKE_C_FLAGS "-Wall -ggdb -O0 -fsanitize=address -fsanitize=undefined")
#set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -ggdb -O0 -fsanitize=address -fsanitize=undefined")

set(CMAKE_C_FLAGS "-Wall -ggdb -O0")
set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -ggdb -O0")


#set(CMAKE_C_FLAGS "-Wall -O2 -DNDEBUG -ggdb")
#set(CMAKE_CXX_FLAGS "-std=c++11 -Wall -O2 -DNDEBUG -ggdb")

add_subdirectory(fmdisk)
add_executable(baidudisk src/baiduapi.cpp src/net.c)
target_link_libraries(baidudisk fmdisk)
