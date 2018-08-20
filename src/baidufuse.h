#ifndef BAIDU_FUSE_H__
#define BAIDU_FUSE_H__

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <fuse.h>

#ifdef  __cplusplus
extern "C" {
#endif

void baidu_prepare();
void *baidu_init(struct fuse_conn_info *conn);
void baidu_destroy(void *);
int baidu_statfs(const char *path, struct statvfs *sf);
int baidu_opendir(const char *path, struct fuse_file_info *fi);
int baidu_readdir(const char* path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi);
int baidu_releasedir(const char* path, struct fuse_file_info *fi);
int baidu_getattr(const char *path, struct stat *st);
int baidu_mkdir(const char *path, mode_t mode);
int baidu_unlink(const char *path);
int baidu_rmdir(const char *path);
int baidu_rename(const char *oldname, const char *newname);
int baidu_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int baidu_open(const char *path, struct fuse_file_info *fi);
int baidu_truncate(const char* path, off_t offset);
int baidu_fgetattr(const char* path, struct stat* st, struct fuse_file_info* fi);
int baidu_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int baidu_ftruncate(const char* path, off_t offset, struct fuse_file_info *fi);
int baidu_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi);
int baidu_fsync(const char *path, int datasync, struct fuse_file_info *fi);
int baidu_flush(const char *path, struct fuse_file_info *fi);
int baidu_release(const char *path, struct fuse_file_info *fi);
int baidu_utimens(const char *path, const struct timespec tv[2]);
int baidu_setxattr(const char *path, const char *name, const char *value, size_t size, int flags);
int baidu_getxattr(const char *path, const char *name, char *value, size_t len);

#ifdef  __cplusplus
}
#endif

#endif
