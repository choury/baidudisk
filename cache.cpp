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

class auto_lock {
    pthread_mutex_t* l;
public:
    auto_lock(pthread_mutex_t* _lock){
        l = _lock;
        pthread_mutex_lock(l);
    }
    ~auto_lock(){
        pthread_mutex_unlock(l);
    }
};


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
size_t GetBlkNo(size_t p, blksize_t blksize)
{
    assert(blksize);
    if (p == 0)
        return 0;
    return (p - 1) / blksize;
}

//计算某位置所在的块的结束位置,分界点算在后一个块中
size_t GetBlkEndPointFromP(size_t p, blksize_t blksize)
{
    assert(blksize);
    return p + blksize - ((long)p + 1) % blksize + 1;
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
    if(dirname(path) == "."){
        return Base64Encode(basename(path).c_str()) + ".def";
    }else{
        return dirname(path)+Base64Encode(basename(path).c_str()) + ".def";
    }
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


int fcache::truncate(size_t size, off_t offset, blksize_t blksize){
    int oc = size / blksize; //原来的块数
    int nc = offset / blksize;   //扩展后的块数
    if(size == (size_t)offset){
        return 0;
    }
    auto_lock l(&Lock);
    int ret = ftruncate(fd, offset);
    int errno_save = errno;
    if(ret < 0){
        return -errno_save;
    }
    if ((size_t)offset > size) {      //文件长度被扩展
        if((chunks[oc].flag & BL_DIRTY) == 0){
            chunks[oc].flag |= BL_DIRTY;
            dirty.insert(&chunks[oc]);
        }
        if(chunks[oc].flag & BL_TRANS) {
            chunks[oc].flag |= BL_REOPEN;
        }
        for(int i=oc+1; i<=nc; ++i){
            assert(chunks.count(i) == 0);
            chunks[i].id = i;
            chunks[i].name = "x";
            chunks[i].flag |= BL_SYNCED;
        }
    }else{
        if((chunks[nc].flag & BL_DIRTY) == 0){
            chunks[nc].flag |= BL_DIRTY;
            dirty.insert(&chunks[nc]);
        }
        if(chunks[nc].flag & BL_TRANS) {
            chunks[nc].flag |= BL_REOPEN;
        }
        for(int i=nc+1; i<=oc; ++i){
            //truncate 掉的就不需要再上传了
            if(chunks[i].flag & BL_DIRTY){
                dirty.erase(&chunks[i]);
                pthread_cond_signal(&wait);
            }
            if(chunks[i].name[0]){
                droped.insert(chunks[i].name);
            }
            chunks.erase(i);
        }
    }
    chunks[nc].atime = time(0);
    return ret;
}

ssize_t fcache::write(const void* buff, size_t size, off_t offset, blksize_t blksize){
    assert(size <= (size_t)blksize);
    auto_lock l(&Lock);
    size_t c = offset / blksize;
    while(dirty.size() >= CACHEC) {
        pthread_cond_wait(&wait, &Lock);
    }
    assert(chunks.count(c));
    fblock& fb = chunks[c];
    if((fb.flag & BL_DIRTY) == 0){
        fb.flag |= BL_DIRTY;
        fb.flag |= BL_SYNCED;
        dirty.insert(&fb);
    }
    if(fb.flag & BL_TRANS) {
        fb.flag |= BL_REOPEN;
    }
    ssize_t ret = pwrite(fd, buff, size, offset);
    int errno_save = errno;
    fb.atime = time(0);
    if(ret < 0){
        return -errno_save;
    }
    return ret;
}

ssize_t fcache::read(void* buff, size_t size, off_t offset, blksize_t blksize) {
    assert(size <= (size_t)blksize);
    size_t c = offset / blksize;
    lock();
    assert(chunks.count(c));
    fblock& fb = chunks[c];
    assert(fb.flag & BL_SYNCED);
    size_t len = std::min(size, GetBlkEndPointFromP(offset, blksize) - (size_t)offset);      //计算最长能读取的字节
    ssize_t ret = pread(fd, buff, len, offset);
    int errno_save = errno;
    fb.atime = time(0);
    unlock();
    if (ret < 0) {                   //读取出错了
        return -errno_save;
    }
    return ret;
}


void fcache::synced(int bno, const char* path) {
    assert(path);
    auto_lock l(&Lock);
    if(chunks.count(bno) &&
       (chunks[bno].flag & BL_REOPEN) == 0)
    {
        if(chunks[bno].name[0] && chunks[bno].name != "x"){
            droped.insert(chunks[bno].name);
        }
        chunks[bno].name = path;
        chunks[bno].flag &= ~BL_DIRTY;
        assert(dirty.count(&chunks[bno]));
        dirty.erase(&chunks[bno]);
        pthread_cond_signal(&wait);
    }else{
        droped.insert(path);
    }
}

fcache::~fcache(){
    close(fd);
    pthread_mutex_destroy(&Lock);
    pthread_cond_destroy(&wait);
}

dcache::dcache(){
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,        //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&Lock, &mutexattr);    //每个临时文件都有一把锁，操作它时如果不能确定没有其他线程也操作它就应该上锁，好多锁啊，真头疼
    pthread_mutexattr_destroy(&mutexattr);
}

void dcache::lock() {
    pthread_mutex_lock(&Lock);
}

void dcache::unlock() {
    pthread_mutex_unlock(&Lock);
}

dcache::~dcache(){
    pthread_mutex_destroy(&Lock);
}


inode_t super_node(nullptr);

inode_t::inode_t(inode_t *parent):parent(parent){
    memset(&st, 0, sizeof(st));
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,        //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&Lock, &mutexattr);
    pthread_mutexattr_destroy(&mutexattr);
}

inode_t::~inode_t(){
    assert(empty());
    del_job((job_func)cache_close, this);
    pthread_mutex_destroy(&Lock);
    if(blocklist){
        json_object_put(blocklist);
    }
    delete dir;
    delete file;
}

bool inode_t::empty(){
    if(dir){
        assert(file == nullptr);
        return dir->entry.empty();
    }
    return true;
}

inode_t* inode_t::add_entry(string path, const struct stat* st) {
    assert(basename(path) == path);
    assert(path != "." && path != "/");
    if(path == ""){
        memcpy(&this->st, st, sizeof(struct stat));
        return this;
    }
    inode_t* i = nullptr;
    dir->lock();
    if(dir->entry.count(path) && dir->entry[path]){
        i = dir->entry[path];
        if(i->dir){
            memcpy(&i->st, st, sizeof(struct stat));
            assert((i->flag & SYNCED) == 0);
            assert(i->file == nullptr);
        }
    }else{
        i = new inode_t(this);
        memcpy(&i->st, st, sizeof(struct stat));
        if(S_ISDIR(st->st_mode)){
            i->dir = new dcache;
        }
        dir->entry[path] = i;
    }
    dir->unlock();
    return i;
}


bool inode_t::clear_cache(){
    auto_lock l(&Lock);
    if(dir){
        assert(file == nullptr);
        for(auto i = dir->entry.begin(); i!= dir->entry.end();){
            if(i->second == nullptr){
                delete i->second;
                i = dir->entry.erase(i);
                continue;
            }
            if(i->second->clear_cache())
            {
                delete i->second;
                i = dir->entry.erase(i);
                continue;
            }
            i++;
        }
        flag &= ~SYNCED;
        return empty();
    }
    if(file){
        assert(dir == nullptr);
        cache_close(this);
        flag &= ~SYNCED;
        return file == nullptr;
    }
    flag &= ~SYNCED;
    return true;
}

inode_t* inode_t::getnode(const string& path) {
    auto_lock l(&Lock);
    if(path == "." || path == "/") {
        return this;
    } else {
        string subpath = subname(path);
        string child_name = childname(path);
        assert(file == nullptr);
        if(dir->entry.count(child_name) == 0) {
            return nullptr;
        }
        return dir->entry[child_name]->getnode(subpath);
    }
}

string inode_t::getname(){
    inode_t* p = parent;
    if(p == nullptr){
        return "";
    }
    p->dir->lock();
    for(auto i:p->dir->entry){
        if(i.second == this){
            p->dir->unlock();
            return i.first;
        }
    }
    p->dir->unlock();
    assert(0);
    return "";
}

string inode_t::getcwd(){
    string path = getname();
    if(flag & CHUNKED){
        assert(S_ISREG(st.st_mode));
        path = encodepath(path);
    }
    inode_t* p = this;
    while((p = p->parent)){
        path = p->getname() +"/"+ path;
    }
    return path;
}

void inode_t::filldir(void *buff, fuse_fill_dir_t filler){
    assert(file == nullptr);
    filler(buff, ".", &st, 0);
    if(parent == nullptr){
        assert(this == &super_node);
        filler(buff, "..", nullptr, 0);
    }else{
        filler(buff, "..", &parent->st, 0);
    }
    dir->lock();
    for (auto i : dir->entry) {
        if(i.second){
            filler(buff, i.first.c_str(), &i.second->st, 0);
        }else{
            filler(buff, i.first.c_str(), nullptr, 0);
        }
    }
    dir->unlock();
}

void inode_t::remove(){
    lock();
    inode_t* p = parent;
    p->dir->entry.erase(getname());
    if(file == nullptr){
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
    assert(file);
    opened--;
    if(opened == 0){
        assert(flag & SYNCED);
        del_job((job_func)filesync, this);
        if( st.st_nlink == 0){
            delete this;
            return;
        }else{
            add_job((job_func)cache_close, this, 300);
        }
    }
    unlock();
}

void inode_t::move(const string& path){
    inode_t* p = super_node.getnode(dirname(path));
    auto_lock l(&Lock);
    parent->dir->entry.erase(getname());
    assert(p->dir->entry.count(basename(path)) == 0);
    p->dir->entry[basename(path)] = this;
    parent = p;
}

int inode_t::lock(){
    return pthread_mutex_lock(&Lock);
}

int inode_t::unlock(){
    return pthread_mutex_unlock(&Lock);
}

inode_t* getnode(const char *path){
    super_node.lock();
    inode_t* node = super_node.getnode(path);
    if(node){
        node->lock();
    }
    super_node.unlock();
    return node;
}

void cache_init(){
    super_node.lock();
    super_node.dir = new dcache;
    super_node.unlock();
}

void cache_close(inode_t* node){
    node->lock();
    if(node->opened == 0){
        assert(node->flag & SYNCED );
        assert(node->file);
        delete node->file;
        node->file = nullptr;
    }
    del_job((job_func)cache_close, node);
    node->unlock();
    return;
}

void cache_destory() {
    super_node.lock();
    super_node.clear_cache();
    super_node.unlock();
}

