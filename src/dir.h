#ifndef DIR_H__
#define DIR_H__
#include "locker.h"

#include <map>

using std::string;

class entry_t;

class dir_t: locker {
#define DIR_PULLED 1
    uint32_t flags = 0;
    time_t mtime;
    std::map<string, entry_t*> entrys;
    void pull();
public:
    dir_t(entry_t* entry, entry_t* parent, time_t mtime);
    virtual ~dir_t();
    entry_t* find(std::string path);
    const std::map<string, entry_t*>& get_entrys();
    entry_t* insert(std::string name, entry_t* entry);
    void erase(std::string name);
    time_t getmtime();
    size_t size();
};

#endif
