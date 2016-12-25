#include <pthread.h>
#include <fuse.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "cache.h"
#include "baiduapi.h"


using namespace std;


//在家目录.baidudisk目录下生成临时缓存文件
static int tempfile()
{
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

rfcache::rfcache(){
    fd = tempfile();
    memset(taskid, 0, sizeof(taskid));
    memset(mask, 0, sizeof(mask));
}

rfcache::~rfcache(){
    close(fd);
}

wfcache::wfcache(){
    fd = tempfile();
    memset(taskid, 0, sizeof(taskid));
    memset(md5, 0, sizeof(md5));
    memset(flags, 0, sizeof(flags));
}

wfcache::~wfcache(){
    close(fd);
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
    pthread_mutex_init(&metalock, &mutexattr);    //每个临时文件都有一把锁，操作它时如果不能确定没有其他线程也操作它就应该上锁，好多锁啊，真头疼
    pthread_mutex_init(&datelock, &mutexattr);    //每个临时文件都有一把锁，操作它时如果不能确定没有其他线程也操作它就应该上锁，好多锁啊，真头疼

    pthread_mutexattr_destroy(&mutexattr);
}

inode_t::~inode_t(){
    assert((type == cache_type::status && rcache == nullptr && wcache == nullptr) ||
           (type == cache_type::read && rcache && wcache == nullptr) ||
           (type == cache_type::write && rcache == nullptr && wcache));
    assert(child.size() == 1);
    pthread_mutex_destroy(&metalock);
    pthread_mutex_destroy(&datelock);
    delete rcache;
    delete wcache;
}

bool inode_t::empty(){
    assert(child.count("..") == 1);
    return child.size() == 1;
}

inode_t* inode_t::mknode(const string& path) {
    if(path == "." || path == "/") {
        return this;
    } else {
        assert(wcache == nullptr && rcache == nullptr && type == cache_type::status);
        string subpath = subname(path);
        string child_name = childname(path);
        if(child.count(child_name) == 0) {
            inode_t* i = new inode_t(this);
            child[child_name] = i;
        }
        return child[child_name]->mknode(subpath);
    }
}

void inode_t::addchildstat(const string& path, struct stat st) {
    lockmeta();
    assert(basename(path) == path);
    assert(wcache == nullptr && rcache == nullptr && type == cache_type::status);
    flag |= SYNCED;
    if(child.count(path) == 0) {
        inode_t* i = new inode_t(this);
        child[path] = i;
    }
    child[path]->st = st;
    unlockmeta();
}

inode_t* inode_t::getnode(const string& path) {
    if(path == "." || path == "/") {
        return this;
    } else {
        assert(wcache == nullptr && rcache == nullptr && type == cache_type::status);
        string subpath = subname(path);
        string child_name = childname(path);
        if(child.count(child_name) == 0) {
            return nullptr;
        }
        return child[child_name]->getnode(subpath);
    }
}
struct stat inode_t::getstat(const string& path) {
    if(path == "." || path == "/") {
        return st;
    } else {
        string subpath = subname(path);
        string child_name = childname(path);
        auto c = child.find(child_name);
        if(c == child.end()) {
            struct stat st;
            st.st_ino = (flag & SYNCED);
            st.st_mode = 0;
            return st;
        } else {
            return child[child_name]->getstat(subpath);
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
    return "";
}

string inode_t::getcwd(){
    lockmeta();
    string path = getname();
    inode_t* p = this;
    while((p = p->child[".."])){
        path = p->getname() +"/"+ path;
    }
    unlockmeta();
    return path;
}

int inode_t::filldir(void *buff, fuse_fill_dir_t filler){
    assert(type == cache_type::status);
    int all = flag & SYNCED;
    for (auto i : child) {
        if(i.first == ".."){
            continue;
        }else if(all){
            filler(buff, i.first.c_str(), &i.second->st, 0);
        }else if(i.second->wcache && (i.second->flag & SYNCED) == 0){
            assert(i.second->type == cache_type::write);
            filler(buff, i.first.c_str(), &i.second->st, 0);
        }
    } 
    return all;
}

void inode_t::remove(){
    lockmeta();
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
        unlockmeta();
        return;
    }
}


void inode_t::release(){
    lockmeta();
    assert(type != cache_type::status);
    filesync(this);
    opened--;
    if(opened == 0){
        assert(flag & SYNCED);
        if( st.st_nlink == 0){
            delete this;
            return;
        }
    }
    unlockmeta();
}

void inode_t::move(const string& path){
    inode_t* p = super_node.getnode(dirname(path));
    lockmeta();
    assert(child.count(".."));
    child[".."]->child.erase(getname());
    p->child[basename(path)] = this;
    child[".."] = p;
    unlockmeta();
}

int inode_t::lockmeta(){
    return pthread_mutex_lock(&metalock);
}

int inode_t::unlockmeta(){
    return pthread_mutex_unlock(&metalock);
}

int inode_t::lockdate(){
    return pthread_mutex_lock(&datelock);
}

int inode_t::unlockdate(){
    return pthread_mutex_unlock(&datelock);
}

//获得一个初始化好的fcache,如果创建成功，此fcache 会被自动加入缓存中
inode_t* newfnode(const char *path, cache_type type) {
    super_node.lockmeta();
    inode_t* node = super_node.mknode(path);
    assert(node->type == cache_type::status);
    if(type == cache_type::read){
        node->rcache = new rfcache();
    }
    if(type == cache_type::write){
        node->wcache = new wfcache();
    }
    node->type = type;
    node->opened = 1;
    super_node.unlockmeta();
    return node;
}

inode_t* getnode(const char *path){
    super_node.lockmeta();
    inode_t* node = super_node.getnode(path);
    if(node){
        node->lockmeta();
    }
    super_node.unlockmeta();
    return node;
}


/* 释放filedec结构体，并从缓存中删除，必须没有被打开，
 * 且没有在同步，即TRANSF标志未置位
 * 否则直接取消ONDELE标志并返回，什么都不干
 * 调用时如果该文件未同步并且是到期释放的就调用fcachesync先同步
 * 成功返回0
 */
/*
int releasenode(inode_t *node) {
    assert(node->type != cache_type::status);
    pthread_mutex_lock(&node->lock);
    if (node->opened == 0 && (node->flag & TRANSF) == 0) {
        if ((node->flag & RELEASE) && (node->flag & SYNCED) == 0) {
            filesync(node);
        }
        pthread_mutex_destroy(&node->lock);
        close(node->fd);
        delete node;
        return 0;
    }
    pthread_mutex_unlock(&node->lock);
    return 1;
}
*/


void addstat(const char *dir, const char *path, const struct stat* st) {
    super_node.lockmeta();
    inode_t *node = super_node.mknode(dir);
    node->addchildstat(path, *st);
    super_node.unlockmeta();
}

struct stat getstat(const char *path) {
    super_node.lockmeta();
    struct stat st = super_node.getstat(path);
    super_node.unlockmeta();
    return st;
}


void invalidcache(const char* path){
    super_node.lockmeta();
    inode_t* node = super_node.getnode(dirname(path));
    if(node){
        node->lockmeta();
        node->flag &= ~SYNCED;
        node->unlockmeta();
    }
    super_node.unlockmeta();
}

inode_t* rmcache(const char *path) {
    super_node.lockmeta();
    inode_t* node = super_node.getnode(path);
    if(node){
        node->remove();
    }
    super_node.unlockmeta();
    return node;
}


void renamecache(const char *oldname, const char *newname) {
    super_node.lockmeta();
    inode_t* node = super_node.getnode(oldname);
    if(node){
        node->move(newname);
    }
    super_node.unlockmeta();
}
