#include <sys/stat.h>
#include <sys/statfs.h>
#include <fuse.h>


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
int filesync(struct inode_t *node);

void *baiduapi_init (struct fuse_conn_info *conn);
int baiduapi_getattr ( const char *path, struct stat *stbuf );
int baiduapi_readdir(const char *path, void *buf, fuse_fill_dir_t filler,off_t offset, struct fuse_file_info *fi);
int baiduapi_statfs(const char *path , struct statvfs * sf);
int baiduapi_open(const char *path, struct fuse_file_info *fi);

int baiduapi_read(const char *path, char *buf, size_t size, off_t offset,struct fuse_file_info *fi);
int baiduapi_create(const char *path, mode_t mode, struct fuse_file_info *fi);
int baiduapi_write ( const char *path,const char *buf, size_t size, off_t offset, struct fuse_file_info *fi );
int baiduapi_release ( const char *path, struct fuse_file_info *fi );
int baiduapi_mkdir ( const char * path, mode_t mode);
int baiduapi_unlink(const char *path);
int baiduapi_rmdir(const char *path);
int baiduapi_rename(const char * oldname,const char *newname);
int baiduapi_fsync (const char *path, int flag, struct fuse_file_info *fi);
int baiduapi_flush(const char * path, struct fuse_file_info *fi);
int baiduapi_truncate(const char * path, off_t offset);
int baiduapi_stub(const char *path);

int baiduapi_uploadfile (int file,const char * path);
int baiduapi_mergertmpfile(const char * path, struct inode_t* node);

#ifdef  __cplusplus
}
#endif
