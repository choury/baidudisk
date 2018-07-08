project(baidudisk)

set(CMAKE_C_FLAGS "-D_FILE_OFFSET_BITS=64 -Wall -ggdb -O0 -fsanitize=address -fsanitize=undefined")
set(CMAKE_CXX_FLAGS "-D_FILE_OFFSET_BITS=64 -std=c++11 -Wall -ggdb -O0 -fsanitize=address -fsanitize=undefined")

#set(CMAKE_C_FLAGS "-D_FILE_OFFSET_BITS=64 -Wall -ggdb -O0")
#set(CMAKE_CXX_FLAGS "-D_FILE_OFFSET_BITS=64 -std=c++11 -Wall -ggdb -O0")


#set(CMAKE_C_FLAGS "-D_FILE_OFFSET_BITS=64 -Wall -O2 -DNDEBUG -ggdb")
#set(CMAKE_CXX_FLAGS "-D_FILE_OFFSET_BITS=64 -std=c++11 -Wall -O2 -DNDEBUG -ggdb")

add_subdirectory(src)
