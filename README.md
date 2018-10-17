baidudisk
=========

a client of baidudisk for linux

** base on fmdisk **

* 由于百度api的限制 [参阅](http://developer.baidu.com/wiki/index.php?title=docs/pcs)，该程序只能处理/apps/Native下面的文件，在网页上显示为 我的应用数据/Native, 你可以把要处理的文件全部都挪到这个文件下面


build
--------
要想编译这个项目，你需要：

以下工具

* cmake
* make
* gcc, g++(需支持c++11)
* 并且安装以下软件包:
libcurl4 libcurl4-openssl json-c libfuse2 libssl 和相应的dev包（如果有）

怎么编译：
```
mkdir build && cd build
cmake .
make
```

如果没有错误，当前目录下面会生成一个名为baidudisk的可执行文件

这个文件使用类似于mount 比如 ./baidudisk disk （disk应为一个空目录)

你的网盘下的文件即可在disk目录下面看到
