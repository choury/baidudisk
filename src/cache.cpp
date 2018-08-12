#include "cache.h"
#include "dir.h"
#include "file.h"
#include "baiduapi.h"
#include "threadpool.h"

#include <string.h>
#include <assert.h>
#include <json-c/json.h>


static string childname(const string& path) {
    size_t pos = path.find_first_of("/");
    if(pos == string::npos) {
        return path;
    }
    if(pos == 0 ) {
        string path_truncate = path.substr(1, path.length());
        return childname(path_truncate);
    }
    return path.substr(0, pos);
}

static string subname(const string& path) {
    size_t pos = path.find_first_of("/");
    if(pos == string::npos || pos == path.length()-1) {
        return ".";
    }
    if(pos == 0 ) {
        string path_truncate = path.substr(1, path.length());
        return subname(path_truncate);
    }
    return path.substr(pos+1, path.length());
}

void cache_prepare() {
    baiduapi_prepare();
}

entry_t* cache_root() {
    creatpool(THREADS);
    start_prefetch();
    start_writeback();
    struct stat st;
    HANDLE_EAGAIN(baiduapi_getattr("/", &st));
    st.st_ino = 0;
    return new entry_t(nullptr, "", &st);
}

int entry_t::statfs(const char* path, struct statvfs* sf) {
    return baiduapi_statfs(path, sf);
}


entry_t::entry_t(entry_t* parent, string name, struct stat* st):
    parent(parent),
    name(name),
    mode(st->st_mode),
    ctime(st->st_ctime),
    flags(ENTRY_INITED)
{
    if(S_ISDIR(mode)){
        dir = new dir_t(this, parent, st->st_mtime);
    }else{
        file = new file_t(this, st);
    }
}

entry_t::entry_t(entry_t* parent, string name):
    parent(parent),
    name(name),
    mode(S_IFREG | 0666),
    flags(ENTRY_CHUNCED)
{
    addtask((taskfunc)pull, this, 0, 0);
}

entry_t::~entry_t() {
    assert(opened == 0);
    pthread_mutex_destroy(&init_lock);
    pthread_cond_destroy(&init_cond);
    if(S_ISDIR(mode)){
        delete dir;
    }else{
        delete file;
    }
}

void entry_t::init_wait() {
    pthread_mutex_lock(&init_lock);
    while((flags & ENTRY_INITED) == 0){
        pthread_cond_wait(&init_cond, &init_lock);
    }
    pthread_mutex_unlock(&init_lock);
}

void entry_t::pull(entry_t* entry) {
    assert(entry->flags & ENTRY_CHUNCED);
    buffstruct bs;
    int ret = HANDLE_EAGAIN(baiduapi_download((entry->getpath()+METAPATH).c_str(), 0, 0, bs));
    if(ret != 0){
        throw "baiduapi IO Error";
    }
    json_object *json_get = json_tokener_parse(bs.buf);
    if(json_get ==  nullptr){
        throw "Json parse error";
    }
    struct stat st;
    memset(&st, 0, sizeof(st));
    json_object* jctime;
    ret = json_object_object_get_ex(json_get, "ctime", &jctime);
    assert(ret);
    entry->ctime = json_object_get_int64(jctime);

    json_object* jmtime;
    ret = json_object_object_get_ex(json_get, "mtime", &jmtime);
    assert(ret);
    st.st_mtime = json_object_get_int64(jmtime);

    json_object* jsize;
    ret = json_object_object_get_ex(json_get, "size", &jsize);
    assert(ret);
    st.st_size = json_object_get_int64(jsize);

    json_object *jencoding;
    ret = json_object_object_get_ex(json_get, "encoding", &jencoding);
    assert(ret);
    const char* encoding = json_object_get_string(jencoding);
    if(strcasecmp(encoding, "xor") == 0){
        st.st_ino = FILE_ENCODE;
    }else{
        assert(strcasecmp(encoding, "none") == 0);
    }

    json_object *jblksize;
    ret = json_object_object_get_ex(json_get, "blksize", &jblksize);
    assert(ret);
    st.st_blksize = json_object_get_int64(jblksize);

    json_object *jblock_list;
    ret = json_object_object_get_ex(json_get, "block_list", &jblock_list);
    assert(ret);

    std::vector<string> fblocks(json_object_array_length(jblock_list));
    for(int i=0; i < json_object_array_length(jblock_list); i++){
        json_object *block = json_object_array_get_idx(jblock_list, i);
        const char* name = json_object_get_string(block);
        fblocks[i] = name;
    }
    json_object_put(json_get);
    entry->file = new file_t(entry, &st, fblocks);
    entry->flags |= ENTRY_INITED;
    pthread_cond_broadcast(&entry->init_cond);
}


void entry_t::clean(entry_t* entry) {
    auto_wlock(entry);
    entry->flags &= ~ENTRY_REASEWAIT;
    if(entry->opened > 0){
        return;
    }
    assert((entry->file->getattr().st_ino & FILE_DIRTY) == 0);
    assert(S_ISREG(entry->mode));
    if(entry->flags & ENTRY_DELETED){
        __w.unlock();
        delete entry;
    }else{
        entry->file->release();
    }
}


string entry_t::getpath() {
    auto_rlock(this);
    if(flags & ENTRY_CHUNCED){
        return encodepath(getcwd());
    }else{
        return getcwd();
    }
}

string entry_t::getcwd() {
    auto_rlock(this);
    if(parent == nullptr){
        return "/";
    }
    if(S_ISDIR(mode)){
        return parent->getcwd() + name + "/";
    }else{
        return parent->getcwd() + name;
    }
}

int entry_t::getattr(struct stat* st) {
    init_wait();
    memset(st, 0, sizeof(struct stat));
    auto_rlock(this);
    st->st_mode = mode;
    st->st_ctime = ctime;
    st->st_nlink = 1;
    if(!S_ISDIR(mode)){
        struct stat fst = file->getattr();
        st->st_size = fst.st_size;
        st->st_blocks = fst.st_blocks;
        st->st_blksize = fst.st_blksize;
        st->st_mtime = fst.st_mtime;
    }else{
        st->st_mtime = dir->getmtime();
    }
    return 0;
}

entry_t* entry_t::find(string path){
    auto_rlock(this);
    if(path == "." || path == "/"){
        return this;
    }
    string cname = childname(path);
    entry_t* entry = dir->find(cname);
    if(entry){
        return entry->find(subname(path));
    }
    return nullptr;
}

entry_t* entry_t::create(string name){
    auto_rlock(this);
    assert(S_ISDIR(mode));
    struct stat st;
    memset(&st, 0 , sizeof(st));
    st.st_ino =  FILE_ENCODE | FILE_DIRTY | FILE_CREATE; //use as file_t flags
    st.st_nlink = 1;
    st.st_size = 0;
    st.st_blksize = BLOCKLEN;
    st.st_mode = S_IFREG | 0666;
    st.st_ctime = time(NULL);
    st.st_mtime = time(NULL);
    entry_t* entry = new entry_t(this, name, &st);
    entry->flags |= ENTRY_CHUNCED;
    int ret = HANDLE_EAGAIN(baiduapi_mkdir(entry->getpath().c_str(), &st));
    if(ret){
        delete entry;
        return nullptr;
    }
    return dir->insert(name, entry);
}

int entry_t::mkdir(string name) {
    if(endwith(name, ".def")){
        return -EINVAL;
    }
    auto_rlock(this);
    assert(S_ISDIR(mode));
    struct stat st;
    memset(&st, 0 , sizeof(st));
    st.st_nlink = 1;
    st.st_size = 0;
    st.st_mode = S_IFDIR | 0755;
    st.st_ctime = time(NULL);
    st.st_mtime = time(NULL);
    entry_t* entry = new entry_t(this, name, &st);
    int ret = HANDLE_EAGAIN(baiduapi_mkdir(entry->getpath().c_str(), &st));
    if(ret){
        delete entry;
        return ret;
    }
    dir->insert(name, entry);
    return 0;
}

int entry_t::open() {
    auto_wlock(this);
    opened++;
    if(S_ISREG(mode) && file->open() < 0){
        return -errno;
    }
    return 0;
}


const std::map<string, entry_t*>& entry_t::entrys(){
    auto_rlock(this);
    return dir->get_entrys();
}


int entry_t::read(void* buff, off_t offset, size_t size) {
    auto_rlock(this);
    return file->read(buff, offset, size);
}

int entry_t::truncate(off_t offset){
    auto_rlock(this);
    if((flags & ENTRY_CHUNCED) == 0){
        return -EPERM;
    }
    int ret = file->truncate(offset);
    if(ret < 0){
        return -errno;
    }
    return ret;
}


int entry_t::write(const void* buff, off_t offset, size_t size) {
    auto_rlock(this);
    if((flags & ENTRY_CHUNCED) == 0){
        return -EPERM;
    }
    int ret = file->write(buff, offset, size);
    if(ret < 0){
        return -errno;
    }
    return ret;
}


int entry_t::sync(int datasync){
    auto_rlock(this);
    if((flags & ENTRY_CHUNCED) == 0){
        return 0;
    }
    assert(S_ISREG(mode));
    file->sync();
    struct stat st = file->getattr();
    if(!datasync && (st.st_ino & FILE_DIRTY)){
        json_object *jobj = json_object_new_object();
        json_object_object_add(jobj, "size", json_object_new_int64(st.st_size));
        json_object_object_add(jobj, "ctime", json_object_new_int64(ctime));
        json_object_object_add(jobj, "mtime", json_object_new_int64(st.st_mtime));
        json_object_object_add(jobj, "blksize", json_object_new_int64(st.st_blksize));
        if(st.st_ino & FILE_ENCODE){
            json_object_object_add(jobj, "encoding", json_object_new_string("xor"));
        }else{
            json_object_object_add(jobj, "encoding", json_object_new_string("none"));
        }
        auto fblocks = file->getfblocks();
        json_object *jblock_list = json_object_new_array();
        for(auto block: fblocks){
            json_object_array_add(jblock_list, json_object_new_string(block.c_str()));
        }
        json_object_object_add(jobj, "block_list", jblock_list);
        const char *jstring = json_object_to_json_string(jobj);

        char path[PATHLEN];
        int ret = HANDLE_EAGAIN(baiduapi_upload((getpath() + METAPATH).c_str(), jstring, strlen(jstring), true, path));
        assert(ret == 0);
        json_object_put(jobj);
        file->post_sync();
    }
    return 0;
}

int entry_t::flush(){
    sync(0);
    return 0;
}

int entry_t::release() {
    {
        auto_wlock(this);
        opened--;
        if(opened || !S_ISREG(mode)){
            return 0;
        }
        flags |= ENTRY_REASEWAIT;
    }
    addtask(taskfunc(clean), this, 0, 60);
    return 0;
}

int entry_t::utime(const struct timespec  tv[2]) {
    auto_rlock(this);
    if((flags & ENTRY_CHUNCED) == 0){
        return -EACCES;
    }
    file->setmtime(tv[1].tv_sec);
    sync(0);
    return 0;
}


void entry_t::insert(string name, entry_t* entry) {
    auto_rlock(this);
    assert(S_ISDIR(mode));
    dir->insert(name, entry);
}


int entry_t::move(entry_t* newparent, string name) {
    auto_wlock(this);
    string oldpath = getpath();
    parent->erase(this->name);
    parent = newparent;
    this->name = name;
    parent->insert(name, this);
    return HANDLE_EAGAIN(baiduapi_rename(oldpath.c_str(), getpath().c_str()));
}

void entry_t::erase(string name) {
    auto_rlock(this);
    assert(S_ISDIR(mode));
    return dir->erase(name);
}

int entry_t::unlink() {
    auto_wlock(this);
    assert(opened == 0);
    if(!S_ISREG(mode)){
        return -EISDIR;
    }
    int ret = HANDLE_EAGAIN(baiduapi_delete(getpath().c_str()));
    if(ret){
        return ret;
    }
    parent->erase(name);
    flags |= ENTRY_DELETED;
    if(flags & ENTRY_REASEWAIT){
        //delete this in clean
        return 0;
    }
    __w.unlock();
    delete this;
    return 0;
}

int entry_t::rmdir() {
    auto_wlock(this);
    if(!S_ISDIR(mode)){
        return -ENOTDIR;
    }
    if(opened){
        return -EBUSY;
    }
    if(dir->get_entrys().size() != 2){
        return -ENOTEMPTY;
    }
    int ret = HANDLE_EAGAIN(baiduapi_delete(getpath().c_str()));
    if(ret){
        return ret;
    }
    parent->erase(name);
    flags |= ENTRY_DELETED;
    if(flags & ENTRY_REASEWAIT){
        return 0;
    }
    __w.unlock();
    delete this;
    return 0;
}
