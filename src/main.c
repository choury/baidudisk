#define FUSE_USE_VERSION 26

#include <fuse.h>

#include "baidufuse.h"

struct fuse_operations baidu_oper = {
    .init       = baidu_init,
    .destroy    = baidu_destroy,
    .getattr    = baidu_getattr,
    .fgetattr   = baidu_fgetattr,
    .opendir    = baidu_opendir,
    .readdir    = baidu_readdir,
    .releasedir = baidu_releasedir,
    .mkdir      = baidu_mkdir,
    .unlink     = baidu_unlink,
    .rmdir      = baidu_rmdir,
    .rename     = baidu_rename,
    .statfs     = baidu_statfs,
    .open       = baidu_open,
    .truncate   = baidu_truncate,
    .read       = baidu_read,
    .create     = baidu_create,
    .write      = baidu_write,
    .flush      = baidu_flush,
    .release    = baidu_release,
    .ftruncate  = baidu_ftruncate,
    .fsync      = baidu_fsync,
    .utimens    = baidu_utimens,
    .getxattr   = baidu_getxattr,
    .setxattr   = baidu_setxattr,
    .flag_nullpath_ok = 1,
    .flag_nopath = 1,

};

int main(int argc, char *argv[]) {
    baidu_prepare();
    return fuse_main(argc, argv, &baidu_oper,NULL);
}
