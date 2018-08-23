#ifndef CACHE_H__
#define CACHE_H__

#include "locker.h"

#include <sys/stat.h>
#include <time.h>

#include <map>

using std::string;

class dir_t;
class file_t;

class entry_t: locker {
    pthread_mutex_t init_lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t  init_cond = PTHREAD_COND_INITIALIZER;
    entry_t* parent;
    string name;
    mode_t mode;
    union{
        dir_t* dir;
        file_t* file;
    };
    time_t ctime = 0;
#define ENTRY_INITED    1
#define ENTRY_CHUNCED   2
#define ENTRY_DELETED   4
#define ENTRY_REASEWAIT 16
    uint32_t flags = 0;
    uint32_t opened = 0;
    void init_wait();
    void erase(string name);
    void insert(string name, entry_t* entry);
    static void pull(entry_t* entry);
    static void push(entry_t* entry);
    static void clean(entry_t* entry);
public:
    static int statfs(const char* path, struct statvfs *sf);
    entry_t(entry_t* parent, string name, struct stat* st);
    entry_t(entry_t* parent, string name);
    virtual ~entry_t();
    string getcwd();
    string getpath();
    int getattr(struct stat* st);
    entry_t* find(string path);
    entry_t* create(string name);
    entry_t* mkdir(string name);
    int open();
    const std::map<string, entry_t*>& entrys();
    int read(void* buff, off_t offset, size_t size);
    int truncate(off_t offset);
    int write(const void* buff, off_t offset, size_t size);
    int sync(int datasync);
    int flush();
    int release();
    int move(entry_t* newparent, string name);
    int utime(const struct timespec tv[2]);
    int unlink();
    int rmdir();
};

void cache_prepare();
entry_t* cache_root();

#endif
