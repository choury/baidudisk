#ifndef __CACHE_H__
#define __CACHE_H__

#include "threadpool.h"
#include <time.h>
#include <semaphore.h>
#include <map>
#include <set>
#include <list>
#include <string>

#include <json-c/json.h>

#define BLOCKLEN      (uint64_t)0x100000          //1M,缓存分块大小 必须为4K的倍数
#define CACHEC        20
    
#define PATHLEN        1024


struct fblock{
    uint32_t id;
    std::string name;
#define BL_SYNCED  1    //已经读取到本地
#define BL_DIRTY   2
#define BL_TRANS   4
#define BL_REOPEN  8
    unsigned char flag = 0;
    time_t atime = time(0);
    fblock(uint32_t id, unsigned char flag, std::string name=""):id(id),name(name), flag(flag){}
};

struct DirtyBlock{
private:
    sem_t cachec;
    std::set<fblock *> dirty;
public:
    DirtyBlock();
    ~DirtyBlock();
    void insert(fblock *);
    void erase(fblock *);
    size_t count(fblock *);
    size_t size();
    std::set<fblock *>::iterator begin();
    std::set<fblock *>::iterator end();
};

struct fcache{
    int fd;
    uint32_t flag;                  //use CHUNKED and ENCRYPT from entry->flag
    pthread_mutex_t Lock;
    std::map<uint32_t, fblock*> chunks;
    std::map<uint32_t, task_t> taskid;
    std::set<std::string> droped;
    DirtyBlock dirty;
    fcache(uint32_t flag);
    void lock();
    void unlock();
    void synced(int bno, const char* path);
    int truncate(size_t size, off_t offset, blksize_t blksize);
    ssize_t write(const void* buff, size_t size, off_t offset, blksize_t blksize);
    ssize_t read(void* buff, size_t size, off_t offset, blksize_t blksize);
    ~fcache();
};

struct entry_t;

struct dcache{
    pthread_mutex_t Lock;
//    std::map<std::string, entry_t*> entrys;
    std::list<entry_t *>entrys;
    std::map<std::string, task_t> taskid;
    dcache();
    void lock();
    void unlock();
    ~dcache();
};

struct entry_t {
private:
    pthread_mutex_t Lock;
public:
    struct stat st;
    struct entry_t* parent;
    std::string path;
    json_object *blocklist = nullptr;
    fcache* file = nullptr;
    dcache* dir = nullptr;
#define META_PULLED      1
#define META_PUSHED      2
#define GETCHILDREN      4
#define CHUNKED           8                       //分块文件,可写
#define ENCRYPT          16                       //xor编码
    uint32_t flag = 0;
    uint32_t opened = 0;
    entry_t(entry_t* parent, std::string path);
    ~entry_t();
    bool empty();
    entry_t* add_entry(std::string path, const struct stat* st);
    entry_t* add_entry(std::string path, entry_t* e);
    bool clear_cache();
    entry_t* getentry(const std::string& path);
    void move(const std::string& path);
    std::string getcwd();
    std::string getname();
    void filldir(void* buff, fuse_fill_dir_t filler);
    int lock();
    int unlock();
    void remove();
    void remove(std::string path);
    void release();
};

size_t GetBlkNo(size_t p, blksize_t blksize);
size_t GetBlkEndPointFromP(size_t p, blksize_t blksize);


std::string dirname(const std::string& path);
std::string basename(const std::string& path);
std::string encodepath(const std::string& path);
std::string decodepath(const std::string& path);
bool endwith(const std::string& s1, const std::string& s2);

entry_t* getentry(const char *path);
void cache_init();
void cache_close(entry_t* node);
void cache_destory();


#endif
