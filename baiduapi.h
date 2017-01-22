#include <sys/stat.h>
#include <sys/statfs.h>
#include <fuse.h>


#define THREADS 50

/*
 * 各api定义参阅http://developer.baidu.com/wiki/index.php?title=docs/pcs/rest/file_data_apis_list
 * 
 */

struct inode_t;

#ifdef  __cplusplus
extern "C" {
#endif

extern char confpath[];
    
typedef struct {
    size_t offset;
    size_t len;
    char *buf;
} buffstruct;


int gettoken();
int refreshtoken();
int filesync(struct inode_t* node, int sync_meta);

void *baidu_init (struct fuse_conn_info *conn);
void baidu_destroy (void *);
int baidu_getattr ( const char *path, struct stat *stbuf );
int baidu_fgetattr(const char* path, struct stat* st, struct fuse_file_info* fi);
int baidu_opendir(const char *path, struct fuse_file_info *fi);
int baidu_readdir(const char *path, void *buf, fuse_fill_dir_t filler,off_t offset, struct fuse_file_info *fi);
int baidu_statfs(const char *path , struct statvfs * sf);
int baidu_open(const char *path, struct fuse_file_info *fi);

int baidu_read(const char *path, char *buf, size_t size, off_t offset,struct fuse_file_info *fi);
int baidu_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int baidu_write ( const char *path,const char *buf, size_t size, off_t offset, struct fuse_file_info *fi );
int baidu_release ( const char *path, struct fuse_file_info *fi );
int baidu_mkdir ( const char * path, mode_t mode);
int baidu_unlink(const char *path);
int baidu_rmdir(const char *path);
int baidu_rename(const char * oldname,const char *newname);
int baidu_fsync (const char *path, int flag, struct fuse_file_info *fi);
int baidu_flush(const char * path, struct fuse_file_info *fi);
int baidu_ftruncate(const char* path, off_t offset, struct fuse_file_info *fi);
int baidu_truncate(const char * path, off_t offset);
int baidu_getxattr(const char *path, const char *name, char *value, size_t len);
int baidu_stub(const char *path);

#ifdef  __cplusplus
}
#endif
