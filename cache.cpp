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

//计算某位置在哪个块中,从0开始计数,分界点算在前一个块中
size_t GetBlkNo(size_t p)
{
    if (p == 0)
        return 0;
    return (p - 1) / BLOCKLEN;
}

//计算某位置所在的块的结束位置,分界点算在后一个块中
size_t GetBlkEndPointFromP(size_t p)
{
    return p + BLOCKLEN - ((long)p + 1) % BLOCKLEN + 1;
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
    return dirname(path)+Base64Encode(basename(path).c_str()) + ".def";
}

string decodepath(const string& path){
    assert(endwith(path, ".def"));
    string base = basename(path);
    return dirname(path)+Base64Decode(base.substr(0, base.length()-4).c_str());
}

fcache::fcache(){
    fd = tempfile();
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,        //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&Lock, &mutexattr);    //每个临时文件都有一把锁，操作它时如果不能确定没有其他线程也操作它就应该上锁，好多锁啊，真头疼
    pthread_mutexattr_destroy(&mutexattr);
    pthread_cond_init(&wait, 0);
}

void fcache::lock(){
    pthread_mutex_lock(&Lock);
}

void fcache::unlock(){
    pthread_mutex_unlock(&Lock);
}


int fcache::truncate(size_t size, off_t offset){
    int oc = size / BLOCKLEN; //原来的块数
    int nc = offset / BLOCKLEN;   //扩展后的块数
    assert(size != (size_t)offset);
    lock();
    int ret = ftruncate(fd, offset);
    if(ret < 0){
        unlock();
        return -errno;
    }
    if ((size_t)offset > size) {      //文件长度被扩展
        for(int i=oc; i<=nc; ++i){
            if((chunks[i].flag & BL_DIRTY) == 0){
                chunks[i].flag |= BL_SYNCED;
                chunks[i].flag |= BL_DIRTY;
                dirty ++;
            }
            if(chunks[i].flag & BL_TRANS) {
                chunks[i].flag |= BL_REOPEN;
            }
        }
    }else{
        if((chunks[nc].flag & BL_DIRTY) == 0){
            chunks[nc].flag |= BL_DIRTY;
            dirty ++;
        }
        if(chunks[nc].flag & BL_TRANS) {
            chunks[nc].flag |= BL_REOPEN;
        }
        for(int i=nc+1; i<=oc; ++i){
            if(chunks[i].flag & BL_DIRTY){
                dirty --;
                pthread_cond_signal(&wait);
            }
            if(chunks[i].name[0]){
                droped.insert(chunks[i].name);
            }
            chunks.erase(i);
        }
    }
    unlock();
    return ret;
}

ssize_t fcache::write(const void* buff, size_t size, off_t offset){
    assert(size <= BLOCKLEN);
    lock();
    size_t c = offset / BLOCKLEN;
    while(dirty >= CACHEC) {
        pthread_cond_wait(&wait, &Lock);
    }
    if((chunks[c].flag & BL_DIRTY) == 0){
        chunks[c].flag |= BL_DIRTY;
        chunks[c].flag |= BL_SYNCED;
        dirty ++;
    }
    if(chunks[c].flag & BL_TRANS) {
        chunks[c].flag |= BL_REOPEN;
    }
    ssize_t ret = pwrite(fd, buff, size, offset);
    unlock();
    if(ret < 0){
        return -errno;
    }
    return ret;
}

void fcache::synced(int bno, const char* path) {
    assert(path);
    assert(strlen(path) <= 19);
    lock();
    if(chunks.count(bno) &&
       (chunks[bno].flag & BL_REOPEN) == 0)
    {
        if(chunks[bno].name[0]){
            droped.insert(chunks[bno].name);
        }
        strcpy(chunks[bno].name, path);
        chunks[bno].flag &= ~BL_DIRTY;
        dirty --;
        pthread_cond_signal(&wait);
    }else{
        droped.insert(path);
    }
    unlock();
}

fcache::~fcache(){
    close(fd);
    pthread_mutex_destroy(&Lock);
    pthread_cond_destroy(&wait);
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
    assert(child.size() == 1);
    del_job((job_func)cache_close, this);
    pthread_mutex_destroy(&Lock);
    if(blocklist){
        free((char *)blocklist-sizeof(struct stat));
    }
    delete cache;
}

bool inode_t::empty(){
    assert(child.count("..") == 1);
    return child.size() == 1;
}

void inode_t::add_cache(string path, struct stat st) {
    lock();
    assert(basename(path) == path);
    if(path == "." || path == "/"){
        this->st = st;
        unlock();
        return;
    }
    if(S_ISDIR(st.st_mode) && endwith(path, ".def")){
        baidu_getattr((getcwd()+"/"+path).c_str(), &st);
        unlock();
        return;
    }
    if(child.count(path) == 0) {
        inode_t* i = new inode_t(this);
        child[path] = i;
    }
    child[path]->st = st;
    unlock();
}

bool inode_t::clear_cache(){
    lock();
    for(auto i = child.begin(); i!= child.end();){
        if(i->first == ".."){
            i++;
            continue;
        }
        if(i->second->cache == nullptr &&
           i->second->clear_cache())
        {
            delete i->second;
            i = child.erase(i);
        }else{
            i++;
        }
    }
    flag &= ~SYNCED;
    unlock();
    return empty();
}

inode_t* inode_t::getnode(const string& path, bool create) {
    if(path == "." || path == "/") {
        return this;
    } else {
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
    if(flag & CHUNKED){
        assert(S_ISREG(st.st_mode));
        path = Base64Encode(path.c_str()) + ".def";
    }
    inode_t* p = this;
    while((p = p->child[".."])){
        path = p->getname() +"/"+ path;
    }
    unlock();
    return path;
}

void inode_t::filldir(void *buff, fuse_fill_dir_t filler){
    assert(cache == nullptr);
    filler(buff, ".", &st, 0);
    for (auto i : child) {
        if(i.second == nullptr){
            assert(i.first == "..");
            assert(this == &super_node);
            filler(buff, "..", nullptr, 0);
        }else{
            filler(buff, i.first.c_str(), &i.second->st, 0);
        }
    } 
}

void inode_t::remove(){
    lock();
    inode_t* p = child[".."];
    p->child.erase(getname());
    if(cache == nullptr){
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
    assert(cache);
    filesync(this, 1);
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
        assert(node->cache);
        delete node->cache;
        node->cache = nullptr;
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

