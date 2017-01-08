#include <pthread.h>
#include <fuse.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "cache.h"
#include "baiduapi.h"
#include "job.h"
#include "utils.h"


using namespace std;


//在家目录.baidudisk目录下生成临时缓存文件
static int tempfile() {
    int fd;
    char tmpfilename[PATHLEN];
    sprintf(tmpfilename, "%s/NativeXXXXXX", confpath);
//    sprintf(tmpfilename, "%s/.baidudisk/NativeXXXXXX", getenv("HOME"));
    if ((fd = mkstemp(tmpfilename)) != -1) {
        /*Unlink the temp file.*/
        unlink(tmpfilename);
    }
    return fd;
}

//获得写缓存块结束位置
size_t GetWriteBlkEndPoint(size_t b)
{
    if (b < WBC / 2) {
        return (b + 1) * LWBS;
    } else {
        return (b + 1) * HWBS - (HWBS - LWBS) * WBC / 2;
    }
}


//获得写缓存块开始位置
size_t GetWriteBlkStartPoint(size_t b)
{
    if (b <= WBC / 2) {
        return b * LWBS;
    } else {
        return b * HWBS - (HWBS - LWBS) * WBC / 2;
    }
}

//计算某位置在哪个块中,从0开始计数,分界点算在前一个块中
size_t GetWriteBlkNo(size_t p)
{
    if (p == 0)
        return 0;
    if (p <= LWBS * WBC / 2) {
        return (p - 1) / LWBS;
    } else {
        return WBC / 2 + (p - LWBS * WBC / 2 - 1) / HWBS;
    }
}

//计算某位置所在的块的结束位置
size_t GetWriteBlkEndPointFromP(size_t p)
{
    if (p <= LWBS * WBC / 2) {
        return p + LWBS - ((long)p - 1) % LWBS + 1;
    } else {
        p = p + (HWBS - LWBS) * WBC / 2;
        return p + HWBS - ((long)p - 1) % HWBS + 1;
    }
}

string basename(const string& path) {
    size_t pos = path.find_last_of("/");
    if(pos == string::npos) {
        return path;
    }
    if(path.length() == 1){
        return path;
    }
    if(pos == path.length() -1 ) {
        string path_truncate = path.substr(0, path.length()-1);
        return basename(path_truncate);
    }
    return path.substr(pos+1, path.length());
}

string dirname(const string& path) {
    size_t pos = path.find_last_of("/");
    if(pos == string::npos) {
        return ".";
    }
    if(path.length() == 1){
        return path;
    }
    if(pos == path.length() -1 ) {
        string path_truncate = path.substr(0, path.length()-1);
        return dirname(path_truncate);
    }
    return path.substr(0, pos+1);
}

string childname(const string& path) {
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

string subname(const string& path) {
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

bool endwith(const string& s1, const string& s2){
    auto l1 = s1.length();
    auto l2 = s2.length();
    if(l1 < l2)
        return 0;
    return !memcmp(s1.data()+l1-l2, s2.data(), l2);
}

string encodepath(const string& path){
    return dirname(path)+Base64Encode(basename(path).c_str()) + ".enc";
}

rfcache::rfcache(){
    fd = tempfile();
    memset(mask, 0, sizeof(mask));
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,        //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&Lock, &mutexattr);    //每个临时文件都有一把锁，操作它时如果不能确定没有其他线程也操作它就应该上锁，好多锁啊，真头疼
    pthread_mutexattr_destroy(&mutexattr);
}

void rfcache::lock(){
    pthread_mutex_lock(&Lock);
}

void rfcache::unlock(){
    pthread_mutex_unlock(&Lock);
}

rfcache::~rfcache(){
    close(fd);
    pthread_mutex_destroy(&Lock);
}

wfcache::wfcache(){
    fd = tempfile();
    memset(md5, 0, sizeof(md5));
    memset(flags, 0, sizeof(flags));
    
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,        //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&Lock, &mutexattr);    //每个临时文件都有一把锁，操作它时如果不能确定没有其他线程也操作它就应该上锁，好多锁啊，真头疼
    pthread_mutexattr_destroy(&mutexattr);
}

void wfcache::lock(){
    pthread_mutex_lock(&Lock);
}

void wfcache::unlock(){
    pthread_mutex_unlock(&Lock);
}

wfcache::~wfcache(){
    close(fd);
    pthread_mutex_destroy(&Lock);
}

inode_t super_node(nullptr);

inode_t::inode_t(inode_t *parent) {
    child[".."] = parent;
    memset(&st, 0, sizeof(st));
    st.st_ctime = time(nullptr);
    st.st_mtime = time(nullptr);
    st.st_nlink = 1;
    st.st_mode = S_IFDIR | 0755;
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,        //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&Lock, &mutexattr);    //每个临时文件都有一把锁，操作它时如果不能确定没有其他线程也操作它就应该上锁，好多锁啊，真头疼
    pthread_mutexattr_destroy(&mutexattr);
}

inode_t::~inode_t(){
    assert((type == cache_type::status && rcache == nullptr && wcache == nullptr) ||
           (type == cache_type::read && rcache && wcache == nullptr) ||
           (type == cache_type::write && rcache == nullptr && wcache));
    assert(child.size() == 1);
    pthread_mutex_destroy(&Lock);
    delete rcache;
    delete wcache;
    del_job((job_func)cache_close, this);
}

bool inode_t::empty(){
    assert(child.count("..") == 1);
    return child.size() == 1;
}

const char* inode_t::add_cache(string path, struct stat st) {
    lock();
    int encrypted = 0;
    assert(basename(path) == path);
    if(path == "." || path == "/"){
        this->st = st;
        unlock();
        return path.c_str();
    }
    if(S_ISREG(st.st_mode) && endwith(path, ".enc")){
        encrypted = ENCRYPT;
        path = Base64Decode(path.substr(0, path.length()-4).c_str());
    }
    assert(wcache == nullptr && rcache == nullptr && type == cache_type::status);
    if(child.count(path) == 0) {
        inode_t* i = new inode_t(this);
        i->flag = encrypted;
        child[path] = i;
    }
    if(child[path]->type != cache_type::write){
        child[path]->st = st;
    }
    unlock();
    return path.c_str();
}

bool inode_t::clear_cache(){
    lock();
    for(auto i = child.begin(); i!= child.end();){
        if(i->first == ".."){
            i++;
            continue;
        }
        if(i->second->type == cache_type::status){
            if(i->second->clear_cache()){
                i = child.erase(i);
            }
        }else{
            i++;
        }
    }
    flag &= ~SYNCED;
    unlock();
    return empty();;
}

inode_t* inode_t::getnode(const string& path, bool create) {
    if(path == "." || path == "/") {
        return this;
    } else {
        assert(wcache == nullptr && rcache == nullptr && type == cache_type::status);
        string subpath = subname(path);
        string child_name = childname(path);
        if(child.count(child_name) == 0) {
            if(create){
                inode_t* i = new inode_t(this);
                child[child_name] = i;
            }else{
                return nullptr;
            }
        }
        return child[child_name]->getnode(subpath, create);
    }
}
const struct stat* inode_t::getstat(const string& path) {
    if(path == "." || path == "/") {
        if(flag & SYNCED){
            return &st;
        }else{
            return nullptr;
        }
    } else {
        string subpath = subname(path);
        string child_name = childname(path);
        auto c = child.find(child_name);
        if(c == child.end()) {
            return nullptr;
        } else {
            return &child[child_name]->st;
        }
    }
}

string inode_t::getname(){
    assert(child.count(".."));
    inode_t* p = child[".."];
    if(p == nullptr){
        return "";
    }
    for(auto i:p->child){
        if(i.second == this){
            return i.first;
        }
    }
    assert(0);
    return "";
}

string inode_t::getcwd(){
    lock();
    string path = getname();
    if(flag & ENCRYPT){
        assert(S_ISREG(st.st_mode));
        path = Base64Encode(path.c_str()) + ".enc";
    }
    inode_t* p = this;
    while((p = p->child[".."])){
        path = p->getname() +"/"+ path;
    }
    unlock();
    return path;
}

int inode_t::filldir(void *buff, fuse_fill_dir_t filler){
    assert(type == cache_type::status);
    int all = flag & SYNCED;
    for (auto i : child) {
        if(i.first == ".."){
            if(i.second){
                filler(buff, "..", &i.second->st, 0);
            }else{
                assert(this == &super_node);
                filler(buff, "..", nullptr, 0);
            }
            continue;
        }
        if(all){
            filler(buff, i.first.c_str(), &i.second->st, 0);
        }else if(i.second->wcache && (i.second->flag & SYNCED) == 0){
            assert(i.second->type == cache_type::write);
            filler(buff, i.first.c_str(), &i.second->st, 0);
        }
    } 
    filler(buff, ".", &st, 0);
    return all;
}

void inode_t::remove(){
    lock();
    inode_t* p = child[".."];
    p->child.erase(getname());
    if(type == cache_type::status){
        assert(wcache == nullptr && rcache == nullptr);
        assert(empty()); //only ".."
        delete this;
        return;
    }else if(opened == 0){
        assert(flag & SYNCED);
        delete this;
        return;
    }else{
        st.st_nlink = 0;
        unlock();
        return;
    }
}


void inode_t::release(){
    lock();
    assert(type != cache_type::status);
    filesync(this);
    opened--;
    if(opened == 0){
        assert(flag & SYNCED);
        if( st.st_nlink == 0){
            delete this;
            return;
        }else{
            add_job(job_func(cache_close), this, 300);
        }
    }
    unlock();
}

void inode_t::move(const string& path){
    inode_t* p = super_node.getnode(dirname(path), true);
    lock();
    assert(child.count(".."));
    child[".."]->child.erase(getname());
    p->child[basename(path)] = this;
    child[".."] = p;
    unlock();
}

int inode_t::lock(){
    return pthread_mutex_lock(&Lock);
}

int inode_t::unlock(){
    return pthread_mutex_unlock(&Lock);
}

inode_t* getnode(const char *path, bool create){
    super_node.lock();
    inode_t* node = super_node.getnode(path, create);
    if(node){
        node->lock();
    }
    super_node.unlock();
    return node;
}

void cache_close(inode_t* node){
    node->lock();
    if(node->opened == 0){
        assert(node->flag & SYNCED );
        assert(node->type != cache_type::status);
        if(node->wcache){
            delete node->wcache;
            node->wcache = nullptr;
        }
        if(node->rcache){
            delete node->rcache;
            node->rcache = nullptr;
        }
        node->type = cache_type::status;
        node->st.st_mode = S_IFREG | 0444;
    }
    del_job((job_func)cache_close, node);
    node->unlock();
    return;
}

void cache_clear() {
    super_node.lock();
    super_node.clear_cache();
    super_node.unlock();
}

