#include "dir.h"
#include "cache.h"
#include "baiduapi.h"

#include <assert.h>


dir_t::dir_t(entry_t* entry, entry_t* parent, time_t mtime): mtime(mtime){
    entrys["."] = entry;
    entrys[".."] = parent ? parent: entry;
}

dir_t::~dir_t(){
    for(auto i: entrys){
        if(i.first != "." && i.first != ".."){
            delete i.second;
        }
    }
}

// Must wlock before call this function
void dir_t::pull() {
    entry_t* entry = entrys["."];
    std::string path = entry->getpath();
    std::map<std::string, struct stat> smap;
    int ret = HANDLE_EAGAIN(baiduapi_list(path.c_str(), MAXFILE, smap));
    if(ret != 0){
        throw "baiduapi IO Error";
    }
    for(auto i: smap){
        std::string bname = basename(i.first);
        if(endwith(bname, ".def") && S_ISDIR(i.second.st_mode)){
            std::string dname = decodepath(bname);
            entrys[dname] = new entry_t(entry, dname);
        }else{
            i.second.st_ino = 0;
            entrys[bname] = new entry_t(entry, bname, &i.second);
        }
    }
    flags |= DIR_PULLED;
}

entry_t* dir_t::find(std::string path) {
    auto_wlock(this);
    if((flags & DIR_PULLED) == 0){
        pull();
    }
    assert(flags & DIR_PULLED);
    if(entrys.count(path)){
        return entrys[path];
    }else{
        return nullptr;
    }
}

const std::map<string, entry_t*>& dir_t::get_entrys(){
    auto_wlock(this);
    if((flags & DIR_PULLED) == 0){
        pull();
    }
    assert(flags & DIR_PULLED);
    for(auto i: entrys){
        if(i.second == nullptr){
            entrys[i.first] = new entry_t(entrys["."], i.first);
        }
    }
    //at least '.' and '..'
    assert(entrys.size() >= 2);
    return entrys;
}

entry_t* dir_t::insert(string name, entry_t* entry){
    auto_wlock(this);
    assert(entrys.count(name) == 0);
    assert(entrys.size() < MAXFILE);
    mtime = time(0);
    return entrys[name] = entry;
}

void dir_t::erase(std::string name) {
    auto_wlock(this);
    assert(entrys.count(name));
    entrys.erase(name);
    mtime = time(0);
}


time_t dir_t::getmtime() {
    auto_rlock(this);
    return mtime;
}

size_t dir_t::size() {
    auto_rlock(this);
    return entrys.size();
}

