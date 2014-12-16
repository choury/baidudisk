baidudisk
=========

a client for baidudisk for linux


要想编译这个项目，你需要：

以下工具
cmake
make
gcc, g++(需支持c++11)

并且安装以下软件包:
libcurl4 libcurl4-openssl libjson libfuse2 libssl 和相应的dev包（如果有）

你的linux内核需要装载fuse模块(lsmod | grep fuse)

参阅http://developer.baidu.com/wiki/index.php?title=docs/pcs
由于百度api的限制，该程序只能处理/apps/Native下面的文件，在网页上显示为 我的应用数据/Native
你可以把要处理的文件全部都挪到这个文件下面

目前最多上传20G文件！！！！！

其实程序运行并不需要图形界面，但是开始获取Access_Token需要浏览器登入帐号，
你也可以在其他电脑获取Access_Token并拷到执行目录下来运行


怎么编译：
cmake .
make

如果没有错误，当前目录下面会生成一个名为baidudisk的可执行文件
这个文件使用类似于mount 比如 ./baidudisk disk （disk应为一个空目录)
你的网盘下的文件即可在disk目录下面看到


