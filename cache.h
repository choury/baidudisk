#ifndef __CACHE_H__
#define __CACHE_H__

#include "threadpool.h"
#include <time.h>
#include <map>
#include <set>
#include <string>

#include <json-c/json.h>

#define BLOCKLEN      (uint64_t)0x100000          //1M,缓存分块大小 必须为4K的倍数
#define CACHEC        20
    
#define PATHLEN        1024


struct fblock{
    std::string name;
#define BL_SYNCED  1
#define BL_DIRTY   2
#define BL_TRANS   4
#define BL_REOPEN  8
#define BL_RETRY   16
    unsigned char flag = 0;
    time_t atime = time(0);
};

struct fcache{
    int fd;
    size_t dirty = 0;
    pthread_mutex_t Lock;
    pthread_cond_t wait;
    std::map<uint32_t, fblock> chunks;
    std::map<uint32_t, task_t> taskid;
    std::set<std::string> droped;
    fcache();
    void lock();
    void unlock();
    void synced(int bno, const char* path);
    int truncate(size_t size, off_t offset, blksize_t blksize);
    ssize_t write(const void* buff, size_t size, off_t offset, blksize_t blksize);
    ssize_t read(void* buff, size_t size, off_t offset, blksize_t blksize);
    ~fcache();
};

struct inode_t;

struct dcache{
    pthread_mutex_t Lock;
    std::map<std::string, inode_t*> entry;
    std::map<std::string, task_t> taskid;
    dcache();
    void lock();
    void unlock();
    ~dcache();
};

struct inode_t {
private:
    pthread_mutex_t Lock;
public:
    struct stat st;
    struct inode_t* parent;
    json_object *blocklist = nullptr;
    fcache* file = nullptr;
    dcache* dir = nullptr;
#define SYNCED         1                        //是否已同步
#define DIRTY          2                        //是否已修改
#define CHUNKED        4                        //分块文件,可写
    uint32_t flag = 0;
    uint32_t opened = 0;
    inode_t(inode_t* parent);
    ~inode_t();
    bool empty();
    inode_t* add_entry(std::string path,const struct stat* st);
    bool clear_cache();
    inode_t* getnode(const std::string& path);
    void move(const std::string& path);
    std::string getcwd();
    std::string getname();
    void filldir(void* buff, fuse_fill_dir_t filler);
    int lock();
    int unlock();
    void remove();
    void release();
    friend void inode_release(inode_t* node);
};

size_t GetBlkNo(size_t p, blksize_t blksize);
size_t GetBlkEndPointFromP(size_t p, blksize_t blksize);


std::string dirname(const std::string& path);
std::string basename(const std::string& path);
std::string encodepath(const std::string& path);
std::string decodepath(const std::string& path);
bool endwith(const std::string& s1, const std::string& s2);

inode_t* getnode(const char *path);
void cache_init();
void cache_close(inode_t* node);
void cache_destory();


#endif
