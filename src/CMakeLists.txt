add_executable(baidudisk cache.cpp net.c utils.cpp baiduapi.cpp  baidufuse.cpp threadpool.cpp main.c dir.cpp file.cpp)
target_link_libraries(baidudisk json-c fuse ssl crypto pthread curl)

add_executable(baiducheck  net.c utils.cpp baiduapi.cpp threadpool.cpp  check.cpp)
target_link_libraries(baiducheck json-c ssl crypto curl pthread)

#add_executable(locker_test locker_test.cpp)
#target_link_libraries(locker_test pthread)
