#ifndef FILE_H__
#define FILE_H__
#include "locker.h"

#include <vector>
#include <map>

using std::string;

class entry_t;
class file_t;
class block_t: locker {
    file_t* file;
    string name;
    const size_t no;
    const off_t offset;
    const size_t size;
#define BLOCK_SYNC   1
#define BLOCK_DIRTY  2
    unsigned int flags = 0;
    time_t atime;
    int staled();
    static void pull(block_t* b);
    static void push(block_t* b);
    friend void prefetch();
    friend void writeback();
public:
    block_t(file_t* file, string name, size_t no, off_t offset, size_t size);
    ~block_t();
    void prefetch(bool wait);
    void makedirty();
    void sync();
    string getname();
    void reset();
};

class file_t: locker {
    entry_t* entry;
    int fd = 0;
    char* inline_data = nullptr;
    size_t size;
    blksize_t blksize;
    time_t   mtime;
#define FILE_ENCODE  1
#define FILE_DIRTY   2
#define FILE_CREATE   4
    uint32_t flags;
    pthread_mutex_t extraLocker = PTHREAD_MUTEX_INITIALIZER;
    std::map<uint32_t, block_t*> blocks;
    std::set<string> droped;
public:
    //for simple native file, use st.st_ino as flags
    file_t(entry_t* entry, const struct stat* st);
    //for chunck block file
    file_t(entry_t* entry, const struct stat* st, std::vector<string> fblocks);
    virtual ~file_t();

    string getpath();
    int putbuffer(void* buffer, off_t offset, size_t size);
    int getbuffer(void* buffer, off_t offset, size_t size);
    struct stat getattr();
    void setmtime(time_t mtime);

    int open();
    int read(void* buff, off_t offset, size_t size);
    int truncate(off_t offset);
    int write(const void* buff, off_t offset, size_t size);
    int sync();
    std::vector<string> getfblocks();
    int release();
    void trim(string name);
    void post_sync();
};

void start_prefetch();
void start_writeback();

#endif
