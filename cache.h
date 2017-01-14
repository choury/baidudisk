#ifndef __CACHE_H__
#define __CACHE_H__

#include "threadpool.h"
#include <time.h>
#include <map>
#include <string>

#define BLOCKLEN      (uint64_t)0x100000          //1M,缓存分块大小
#define CACHEC        10
    
#define PATHLEN        1024


struct fblock{
    char name[20];
#define BL_SYNCED  1
#define BL_DIRTY   2
#define BL_TRANS   4
#define BL_REOPEN  8
    unsigned char flag = 0;
};

struct fcache{
    int fd;
    size_t dirty = 0;
    pthread_mutex_t Lock;
    pthread_cond_t wait;
    std::map<uint32_t, fblock> chunks;
    std::map<uint32_t, task_t> taskid;
    fcache();
    void lock();
    void unlock();
    void synced(int bno, const char* path);
    int truncate(size_t size, off_t offset);
    ssize_t write(const void* buff, size_t size, off_t offset);
    ~fcache();
};

struct inode_t {
private:
    pthread_mutex_t Lock;
    std::map<std::string, inode_t*> child;
public:
    struct stat st;
    char (*blocklist)[20] = nullptr;
    fcache* cache = nullptr;
#define SYNCED         1                        //是否已同步
#define CHUNKED        2                        //加密文件
    uint32_t flag = 0;
    uint32_t opened = 0;
    inode_t(inode_t *parent);
    ~inode_t();
    bool empty();
    void add_cache(std::string path, struct stat st);
    bool clear_cache();
    inode_t* getnode(const std::string& path, bool create);
    const struct stat* getstat(const std::string& path);
    void move(const std::string& path);
    std::string getcwd();
    std::string getname();
    int filldir(void *buff, fuse_fill_dir_t filler);
    int lock();
    int unlock();
    void remove();
    void release();
    friend void inode_release(inode_t* node);
};

size_t GetBlkNo(size_t p);
size_t GetBlkEndPointFromP(size_t p);


std::string dirname(const std::string& path);
std::string basename(const std::string& path);
std::string encodepath(const std::string& path);
std::string decodepath(const std::string& path);
bool endwith(const std::string& s1, const std::string& s2);

inode_t* getnode(const char *path, bool create);
void cache_close(inode_t* node);
void cache_clear();


#endif
