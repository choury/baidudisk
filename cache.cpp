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

sem_t global_cachec;

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

DirtyBlock::DirtyBlock(){
    pthread_mutex_init(&lock, nullptr);
    sem_init(&cachec, 0 , CACHEC);
}

DirtyBlock::~DirtyBlock(){
    pthread_mutex_destroy(&lock);
    sem_destroy(&cachec);
}

void DirtyBlock::insert(fblock* fb){
    auto_lock _l(&lock);
    if(dirty.count(fb)){
        return;
    }
    sem_wait(&global_cachec);
    sem_wait(&cachec);
    dirty.insert(fb);
}

void DirtyBlock::erase(fblock* fb){
    auto_lock _l(&lock);
    if(!dirty.count(fb)){
        return;
    }
    sem_post(&global_cachec);
    sem_post(&cachec);
    dirty.erase(fb);
}

size_t DirtyBlock::count(fblock* fb){
    return dirty.count(fb);
}

size_t DirtyBlock::size(){
    return dirty.size();
}

std::set<fblock *>::iterator DirtyBlock::begin(){
    return dirty.begin();
}

std::set<fblock *>::iterator DirtyBlock::end(){
    return dirty.end();
}

fcache::fcache(uint32_t flag): flag(flag){
    fd = tempfile();
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,        //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&Lock, &mutexattr);    //每个临时文件都有一把锁，操作它时如果不能确定没有其他线程也操作它就应该上锁，好多锁啊，真头疼
    pthread_mutexattr_destroy(&mutexattr);
}

void fcache::lock(){
    pthread_mutex_lock(&Lock);
}

void fcache::unlock(){
    pthread_mutex_unlock(&Lock);
}


int fcache::truncate(size_t size, off_t offset, blksize_t blksize){
    int oc = GetBlkNo(size, blksize); //原来的块数
    int nc = GetBlkNo(offset, blksize);   //扩展后的块数

    if(size == (size_t)offset){
        return 0;
    }
    auto_lock l(&Lock);
    int ret = ftruncate(fd, offset);
    if(ret < 0){
        return -errno;
    }
    if ((size_t)offset > size) {      //文件长度被扩展
        assert(chunks[oc]->flag & BL_SYNCED);
        if((chunks[oc]->flag & BL_DIRTY) == 0){
            chunks[oc]->flag |= BL_DIRTY;
            unlock();
            dirty.insert(chunks[oc]);
            lock();
        }
        if(chunks[oc]->flag & BL_TRANS) {
            chunks[oc]->flag |= BL_REOPEN;
        }
        for(int i=oc+1; i<=nc; ++i){
            assert(chunks.count(i) == 0);
            chunks[i] = new fblock(i, BL_SYNCED, "x");
        }
    }else{
        assert(chunks[nc]->flag & BL_SYNCED);
        if((chunks[nc]->flag & BL_DIRTY) == 0){
            chunks[nc]->flag |= BL_DIRTY;
            unlock();
            dirty.insert(chunks[nc]);
            lock();
        }
        if(chunks[nc]->flag & BL_TRANS) {
            chunks[nc]->flag |= BL_REOPEN;
        }
        for(int i=nc+1; i<=oc; ++i){
            //truncate 掉的就不需要再上传了
            if(chunks[i]->flag & BL_DIRTY){
                dirty.erase(chunks[i]);
            }
            if(chunks[i]->name[0]){
                droped.insert(chunks[i]->name);
            }
            delete chunks[i];
            chunks.erase(i);
        }
    }
    chunks[nc]->atime = time(0);
    return ret;
}

ssize_t fcache::write(const void* buff, size_t size, off_t offset, blksize_t blksize){
    assert(size <= (size_t)blksize);
    auto_lock l(&Lock);
    size_t c = offset / blksize;
    assert(chunks.count(c));
    fblock* fb = chunks[c];
    if((fb->flag & BL_DIRTY) == 0){
        fb->flag |= BL_DIRTY;
        fb->flag |= BL_SYNCED;
        unlock();
        dirty.insert(fb);
        lock();
    }
    if(fb->flag & BL_TRANS) {
        fb->flag |= BL_REOPEN;
    }
    ssize_t ret = pwrite(fd, buff, size, offset);
    int errno_save = errno;
    fb->atime = time(0);
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
    fblock* fb = chunks[c];
    assert(fb->flag & BL_SYNCED);
    size_t len = std::min(size, GetBlkEndPointFromP(offset, blksize) - (size_t)offset);      //计算最长能读取的字节
    ssize_t ret = pread(fd, buff, len, offset);
    int errno_save = errno;
    fb->atime = time(0);
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
       (chunks[bno]->flag & BL_REOPEN) == 0)
    {
        if(chunks[bno]->name[0] && chunks[bno]->name != "x"){
            droped.insert(chunks[bno]->name);
        }
        chunks[bno]->name = path;
        chunks[bno]->flag &= ~BL_DIRTY;
        assert(dirty.count(chunks[bno]));
        dirty.erase(chunks[bno]);
    }else{
        droped.insert(path);
    }
}

fcache::~fcache(){
    close(fd);
    pthread_mutex_destroy(&Lock);
    for(auto fb : chunks){
        delete fb.second;
    }
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


entry_t super_node(nullptr, "");

entry_t::entry_t(entry_t *parent, string path):parent(parent), path(path){
    memset(&st, 0, sizeof(st));
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,        //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&Lock, &mutexattr);
    pthread_mutexattr_destroy(&mutexattr);
}

entry_t::~entry_t(){
    assert(empty());
    del_job((job_func)cache_close, this);
    pthread_mutex_destroy(&Lock);
    if(blocklist){
        json_object_put(blocklist);
    }
    delete dir;
    delete file;
}

bool entry_t::empty(){
    if(dir){
        assert(file == nullptr);
        return dir->entrys.empty();
    }
    return true;
}

entry_t* entry_t::add_entry(string path, const struct stat* st) {
    assert(basename(path) == path);
    assert(path != "." && path != "/" && path != "..");
    entry_t* e = nullptr;
    auto_lock l(&Lock);
    if(path == ""){
        e = this;
    }else{
        auto_lock _l(&dir->Lock);
        for(auto d : dir->entrys){
            if(d->path == path){
                e = d;
            }
        }
    }
    if(e == nullptr){
        e = new entry_t(this, path);
        dir->entrys.push_back(e);
    }
    if(st){
        memcpy(&e->st, st, sizeof(struct stat));
        if(S_ISDIR(st->st_mode) && e->dir == nullptr){
            e->dir = new dcache;
        }
        e->flag = META_PULLED | META_PUSHED;
    }
    return e;
}

entry_t * entry_t::add_entry(std::string path, entry_t* e) {
    assert(basename(path) == path);
    assert(path != "." && path != "/" && path != ".." && path != "");
    auto_lock l(&Lock);
    auto_lock _l(&dir->Lock);
    dir->entrys.push_back(e);
    e->parent = this;
    e->path = path;
    return e;
}

bool entry_t::clear_cache(){
    auto_lock l(&Lock);
    if(opened != 0){
        return false;
    }
    if(dir){
        assert(file == nullptr);
        for(auto i = dir->entrys.begin(); i!= dir->entrys.end();){
            if((*i)->clear_cache()) {
                delete *i;
                i = dir->entrys.erase(i);
                continue;
            }
            i++;
        }
        flag &= ~GETCHILDREN;
        return empty();
    }
    if(file){
        assert(dir == nullptr);
        cache_close(this);
        return file == nullptr;
    }
    return true;
}

entry_t* entry_t::getentry(const string& path) {
    if(path == "." || path == "/") {
        return this;
    } else {
        string subpath = subname(path);
        string child_name = childname(path);
        assert(file == nullptr);
        auto_lock _l(&dir->Lock);
        for(auto e: dir->entrys){
            if(e->path == child_name){
                e->lock();
                this->unlock();
                return e->getentry(subpath);
            }
        }
        this->unlock();
        return nullptr;
    }
}

string entry_t::getname(){
    return path;
}

string entry_t::getcwd(){
    string path;
    if(flag & CHUNKED){
        assert((flag & META_PULLED)== 0 || S_ISREG(st.st_mode));
        path = encodepath(this->path);
    }else{
        path = this->path;
    }
    entry_t* p = this;
    while((p = p->parent)){
        path = p->getname() +"/"+ path;
    }
    if(path == "")
        return "/";
    else
        return path;
}

void entry_t::filldir(void *buff, fuse_fill_dir_t filler){
    assert(file == nullptr);
    filler(buff, ".", &st, 0);
    if(parent == nullptr){
        assert(this == &super_node);
        filler(buff, "..", nullptr, 0);
    }else{
        filler(buff, "..", &parent->st, 0);
    }
    dir->lock();
    for (auto i : dir->entrys) {
        filler(buff, i->path.c_str(), &i->st, 0);
    }
    dir->unlock();
}

void entry_t::remove(std::string path){
    auto_lock l(&Lock);
    auto_lock _l(&dir->Lock);
    for(auto i = dir->entrys.begin(); i!= dir->entrys.end(); i++){
        if((*i)->path == path) {
            dir->entrys.erase(i);
            return;
        }
    }
}

void entry_t::remove(){
    lock();
    parent->remove(path);
    if(file == nullptr){
        assert(empty()); //only ".."
        delete this;
        return;
    }else if(opened == 0){
        assert(flag & META_PUSHED);
        delete this;
        return;
    }else{
        st.st_nlink = 0;
        unlock();
        return;
    }
}


void entry_t::release(){
    lock();
    assert(file);
    if(opened == 0){
        assert(flag & META_PUSHED);
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

void entry_t::move(const string& path){
    string dname = dirname(path);
    string bname = basename(path);
    auto_lock l(&Lock);
    parent->remove(this->path);
    entry_t* p = ::getentry(dname.c_str());
    p->add_entry(bname, this);
    p->unlock();
}

int entry_t::lock(){
    return pthread_mutex_lock(&Lock);
}

int entry_t::unlock(){
    return pthread_mutex_unlock(&Lock);
}

entry_t* getentry(const char *path){
    return getentryAt(&super_node, path);
}

entry_t* getentryAt(entry_t* parent, const std::string& path){
    parent->lock();
    return parent->getentry(path);
}

void cache_init(){
    sem_init(&global_cachec, 0, 2 * CACHEC);
    super_node.lock();
    super_node.dir = new dcache;
    super_node.unlock();
}

void cache_close(entry_t* node){
    node->lock();
    if(node->opened == 0){
        assert(node->flag & META_PUSHED);
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
    sem_destroy(&global_cachec);
}

