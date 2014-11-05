#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>

#include "baiduapi.h"
#include "threadpool.h"
#include "net.h"

char confpath[1024];

struct fuse_operations baiduapi_oper = {
    .init       = baiduapi_init,
    .getattr    = baiduapi_getattr,
    .readdir    = baiduapi_readdir,
    .mkdir      = baiduapi_mkdir,
    .unlink     = baiduapi_unlink,
    .rmdir      = baiduapi_rmdir,
    .link       = baiduapi_link,
    .rename     = baiduapi_rename,
    .statfs     = baiduapi_statfs,
    .open       = baiduapi_open,
    .read       = baiduapi_read,
    .create     = baiduapi_create,
    .write      = baiduapi_write,
    .release    = baiduapi_release,
    .access     = baiduapi_access,
    .utimens    = baiduapi_utimens,
    .fsync      = baiduapi_fsync,
};


int main(int argc, char *argv[]) {
    netinit();                          //初始化网络
    sprintf(confpath, "%s/.baidudisk", getenv("HOME"));
    while(gettoken());                  //取得access_token
    return fuse_main(argc, argv, &baiduapi_oper,NULL);
}
