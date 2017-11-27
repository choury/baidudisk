baidudisk
=========

a client for baidudisk for linux

**自己从其他地方上传的文件可以正常读取,但是显示为只读文件，本程序上传的文件只能由本程序读写，并不能由其他程序读写**

原理：将文件切分成小块文件，修改的时候只需要替换其中某个数据块来达到修改文件的目的。每个文件生成一个[[base64]].def 结尾的目录，目录下面meta.json文件保存了文件的元信息，其中包括所有数据块文件的列表

* 你的linux内核需要装载fuse模块(lsmod | grep fuse)
* 由于百度api的限制 [参阅](http://developer.baidu.com/wiki/index.php?title=docs/pcs)，该程序只能处理/apps/Native下面的文件，在网页上显示为 我的应用数据/Native, 你可以把要处理的文件全部都挪到这个文件下面
* 目前最多上传20G文件！！！！！
* 其实程序运行并不需要图形界面，但是开始获取Access_Token需要浏览器登入帐号，你也可以在其他电脑获取Access_Token并拷到执行目录下来运行


要想编译这个项目，你需要：

以下工具

* cmake
* make
* gcc, g++(需支持c++11)
* 并且安装以下软件包:
libcurl4 libcurl4-openssl json-c libfuse2 libssl 和相应的dev包（如果有）

怎么编译：
```
cmake .
make
```

如果没有错误，当前目录下面会生成一个名为baidudisk的可执行文件

这个文件使用类似于mount 比如 ./baidudisk disk （disk应为一个空目录)

你的网盘下的文件即可在disk目录下面看到
