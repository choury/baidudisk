#ifndef __CACHE_H__
#define __CACHE_H__

#include "threadpool.h"
#include <time.h>
#include <map>
#include <string>

#define RBS            (uint64_t)0x100000         //1M,读缓存分块大小
#define LWBS           (uint64_t)0x800000         //8M,前一半分块大小
#define HWBS           (uint64_t)0x2000000        //32M,后一半分块大小
#define RBC            (uint64_t)20480            //读缓存个数, 最多20G
#define WBC            (uint64_t)1024             //写缓存分块个数，百度定的，最大1024
#define MAXCACHE       20
    
#define PATHLEN        1024



struct rfcache{
    int fd;
    task_t taskid[RBC];
    unsigned int mask[RBC/32+1];                //为1代表已经从服务器成功读取
    rfcache();
    ~rfcache();
};

struct wfcache{
    int fd;
    char md5[WBC][35];
    task_t taskid[WBC];
//每一个block有3位标志位：是否为脏块, 是否在同步,同步时是否被写
#define WF_DIRTY   1
#define WF_TRANS   2
#define WF_REOPEN  4
    unsigned char flags[WBC];
    wfcache();
    ~wfcache();
};


enum class cache_type{status, read, write};

struct inode_t {
private:
    pthread_mutex_t metalock;
    pthread_mutex_t datelock;
    std::map<std::string, inode_t*> child;
public:
    cache_type type = cache_type::status;
    struct stat st;
#define SYNCED         1                        //是否已同步
#define ENCRYPT        2                        //加密文件
    uint32_t flag = 0;
    uint32_t opened = 0;
    rfcache* rcache = nullptr;
    wfcache* wcache = nullptr;
    inode_t(inode_t *parent);
    ~inode_t();
    bool empty();
    const char* add_cache(std::string path, struct stat st);
    void clear_cache();
    inode_t* getnode(const std::string& path, bool create);
    const struct stat* getstat(const std::string& path);
    void move(const std::string& path);
    std::string getcwd();
    std::string getname();
    int filldir(void *buff, fuse_fill_dir_t filler);
    int lockmeta();
    int unlockmeta();
    int lockdate();
    int unlockdate();
    void remove();
    void release();
    friend void inode_release(inode_t* node);
};

typedef void (*eachfunc)(inode_t* node);

size_t GetWriteBlkStartPoint(size_t b);
size_t GetWriteBlkEndPoint(size_t b);
size_t GetWriteBlkNo(size_t p);
size_t GetWriteBlkEndPointFromP(size_t p);
#define GetWriteBlkSize(b)  ((b)<WBC/2?LWBS:HWBS)

std::string dirname(const std::string& path);
std::string basename(const std::string& path);
std::string encodepath(const std::string& path);
bool endwith(const std::string& s1, const std::string& s2);

inode_t* getnode(const char *path, bool create);
void cache_close(inode_t* node);


#endif
