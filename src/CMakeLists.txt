add_executable(baidudisk cache.cpp net.c utils.cpp baiduapi.cpp  baidufuse.cpp threadpool.cpp main.c dir.cpp file.cpp)
target_link_libraries(baidudisk json-c fuse ssl crypto pthread curl)

#add_executable(locker_test locker_test.cpp)
#target_link_libraries(locker_test pthread)
