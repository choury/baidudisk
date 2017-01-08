project(baidudisk)

add_executable(baidudisk cache.cpp net.c utils.cpp baiduapi.cpp threadpool.cpp job.cpp main.c)

install(TARGETS baidudisk RUNTIME DESTINATION bin)

set(CMAKE_C_FLAGS "-D_FILE_OFFSET_BITS=64 -Wall -ggdb -O0")
set(CMAKE_CXX_FLAGS "-D_FILE_OFFSET_BITS=64 -std=c++11 -Wall -ggdb -O0")

target_link_libraries(baidudisk json-c fuse ssl crypto pthread curl)
