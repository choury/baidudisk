#include "file.h"
#include "cache.h"
#include "common.h"
#include "baiduapi.h"
#include "threadpool.h"

#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <semaphore.h>

#include <list>

sem_t read_sem;
pthread_mutex_t readlock = PTHREAD_MUTEX_INITIALIZER;
std::list<block_t*> readlist;

sem_t dirty_sem;
pthread_mutex_t writelock = PTHREAD_MUTEX_INITIALIZER;
std::list<block_t*> writelist;

static bool findinqueue(std::list<block_t*>& list, block_t* b){
    for(auto i: list){
        if(i == b){
            return true;
        }
    }
    return false;
}

static bool liftorpush(std::list<block_t*>& list, block_t* b){
    bool found = false;
    for(auto i = list.begin(); i != list.end(); i++ ){
        if(*i == b){
            found = true;
            list.erase(i);
            break;
        }
    }
    list.push_back(b);
    return found;
}

void prefetch() {
    while(true){
        sem_wait(&read_sem);
        pthread_mutex_lock(&readlock);
        if(readlist.empty()){
            pthread_mutex_unlock(&readlock);
            continue;
        }
        block_t* b = readlist.front();
        readlist.pop_front();
        pthread_mutex_unlock(&readlock);
        b->pull();
    }
}

void writeback(){
    while(true){
        sleep(1);
        pthread_mutex_lock(&writelock);
        if(writelist.empty()){
            pthread_mutex_unlock(&writelock);
            continue;
        }
        while(writelist.size() >= THREADS/2){
            addtask((taskfunc)block_t::push, writelist.front(), 0, 0);
            writelist.pop_front();
        }
        for(auto i = writelist.begin(); i!= writelist.end();){
            if((*i)->staled() >= 30){
                addtask((taskfunc)block_t::push, *i, 0, 0);
                i = writelist.erase(i);
            }else{
                break;
            }
        }
        pthread_mutex_unlock(&writelock);
    }
}

void start_prefetch() {
    sem_init(&read_sem, 0, 0);
    for(int i = 0; i < THREADS/2; i++){
        addtask((taskfunc)prefetch, nullptr, 0, 0);
    }
}

void start_writeback(){
    sem_init(&dirty_sem, 0, THREADS/4);
    addtask((taskfunc)writeback, nullptr, 0, 0);
}

block_t::block_t(file_t* file, string name, size_t no, off_t offset, size_t size):
    file(file),
    name(name),
    no(no),
    offset(offset),
    size(size)
{
    if(name == "x"){
        flags = BLOCK_SYNC;
    }
}

block_t::~block_t() {
    pthread_mutex_lock(&readlock);
    for(auto i =  readlist.begin(); i != readlist.end(); ){
        if(*i == this){
            i = readlist.erase(i);
        }else{
            i++;
        }
    }
    pthread_mutex_unlock(&readlock);
    pthread_mutex_lock(&writelock);
    for(auto i = writelist.begin(); i != writelist.end();){
        if(*i ==  this){
            i = writelist.erase(i);
            sem_post(&dirty_sem);
        }else{
            i++;
        }
    }
    pthread_mutex_unlock(&writelock);
    auto_wlock(this);
    file->trim(name);
}

int block_t::pull() {
    auto_wlock(this);
    if(flags & BLOCK_SYNC){
        return 0;
    }
    buffstruct bs((char*)malloc(size), size);
    //for chunk file, read from begin
    off_t startp = name.size() ? 0 : offset;
    int ret = HANDLE_EAGAIN(baiduapi_download((file->getpath()+"/"+name).c_str(), startp, size, bs));
    assert(bs.offset <= (size_t)size);
    if(ret == 0){
        file->putbuffer(bs.buf, offset, bs.offset);
        flags |= BLOCK_SYNC;
    }
    return ret;
}

void block_t::push(block_t* b) {
    string path = b->file->getpath();
    auto_wlock(b);
    assert(b->flags & BLOCK_DIRTY);
    char *buff = (char*)malloc(b->size);
    size_t len = b->file->getbuffer(buff, b->offset, b->size);
    b->file->trim(b->name);
    if(len){
        //It must be chunk file, because native file can't be written
        char inpath[PATHLEN];
        snprintf(inpath, sizeof(inpath)-1, "%s/%zu", path.c_str(), b->no);
        char outpath[PATHLEN];
        int ret = HANDLE_EAGAIN(baiduapi_upload(inpath, buff, len, false, outpath));
        free(buff);
        if(ret != 0){
            throw "baiduapi IO Error";
        }
        b->name = outpath + path.length() + 1;
    }else{
        b->name = "x";
    }
    b->flags &= ~BLOCK_DIRTY;
    sem_post(&dirty_sem);
}

void block_t::prefetch(bool wait) {
    if(wait){
        if(pull()){
            throw "baiduapi IO Error";
        }
        return;
    }
    if(tryrlock()){
        return;
    }
    if(flags & BLOCK_SYNC){
        unrlock();
        return;
    }
    unrlock();
    pthread_mutex_lock(&readlock);
    if(!findinqueue(readlist, this) && readlist.size() <= THREADS/2){
        sem_post(&read_sem);
        readlist.push_back(this);
    }
    pthread_mutex_unlock(&readlock);
}

void block_t::makedirty() {
    wlock();
    atime = time(0);
    pthread_mutex_lock(&writelock);
    bool found = liftorpush(writelist, this);
    pthread_mutex_unlock(&writelock);
    assert((found && (flags & BLOCK_DIRTY)) || (!found && (flags & BLOCK_DIRTY)==0));
    flags |=  BLOCK_DIRTY;
    unwlock();
    if(!found){
        sem_wait(&dirty_sem);
    }
}

void block_t::sync(){
    pthread_mutex_lock(&writelock);
    for(auto i = writelist.begin(); i != writelist.end();){
        if(*i ==  this){
            addtask((taskfunc)block_t::push, this, 0, 0);
            i = writelist.erase(i);
            break;
        }else{
            i++;
        }
    }
    pthread_mutex_unlock(&writelock);
    rlock();
    while(flags & BLOCK_DIRTY){
        //TODO notify by thread_cond
        unrlock();
        sleep(1);
        rlock();
    }
    unrlock();
}

string block_t::getname(){
    return name;
}

void block_t::reset(){
    auto_wlock(this);
    assert((flags & BLOCK_DIRTY) == 0);
    if(name == "x"){
        flags = BLOCK_SYNC;
    }else{
        flags = 0;
    }
}

int block_t::staled(){
    auto_rlock(this);
    return time(0) - atime;
}

//在家目录.baidudisk目录下生成临时缓存文件
static int tempfile() {
    int fd;
    char tmpfilename[PATHLEN];
    sprintf(tmpfilename, "%s/NativeXXXXXX", COFPATH);
    if ((fd = mkstemp(tmpfilename)) != -1) {
        /*Unlink the temp file.*/
        unlink(tmpfilename);
    }
    return fd;
}

//计算某位置在哪个块中,从0开始计数,分界点算在前一个块中
static size_t GetBlkNo(size_t p, blksize_t blksize) {
    assert(blksize);
    if (p == 0)
        return 0;
    return (p - 1) / blksize;
}

file_t::file_t(entry_t *entry, const struct stat* st):
    entry(entry),
    size(st->st_size),
    blksize(st->st_blksize),
    mtime(st->st_mtime),
    flags(st->st_ino)
{
    if(flags & FILE_CREATE){
    //creata new file
        assert(size == 0);
        flags &= ~FILE_CREATE;
        blocks[0] = new block_t(this, "x", 0, 0, blksize);
        return;
    }
    for(size_t i = 0; i <= GetBlkNo(size, blksize); i++ ){
        blocks[i] = new block_t(this, "", i, blksize * i, blksize);
    }
}

file_t::file_t(entry_t* entry, const struct stat* st, std::vector<std::string> fblocks):
    entry(entry),
    size(st->st_size),
    blksize(st->st_blksize),
    mtime(st->st_mtime),
    flags(st->st_ino)
{
    //zero is the first block
    assert(fblocks.size() == GetBlkNo(size, blksize)+1);
    for(size_t i = 0; i < fblocks.size(); i++ ){
        blocks[i] = new block_t(this, fblocks[i], i, blksize * i, blksize);
    }
}

file_t::~file_t() {
    auto_wlock(this);
    for(auto i: blocks){
        delete i.second;
    }
    if(fd){
        close(fd);
    }
    pthread_mutex_destroy(&extraLocker);
}

int file_t::open(){
    auto_wlock(this);
    if(fd){
        return 0;
    }
    fd = tempfile();
    if(fd > 0){
        TEMP_FAILURE_RETRY(ftruncate(fd, size));
    }
    return fd;
}

int file_t::read(void* buff, off_t offset, size_t size) {
    auto_rlock(this);
    if((size_t)offset > this->size){
        return -EFAULT;
    }
    if(offset + size > this->size){
        size = this->size - offset;
    }
    size_t startc = GetBlkNo(offset, blksize);
    size_t endc = GetBlkNo(offset + size, blksize);
    for(size_t i = startc; i< endc + 10 && i<= GetBlkNo(this->size, blksize); i++){
        blocks[i]->prefetch(false);
    }
    for(size_t i = startc; i<= endc; i++ ){
        blocks[i]->prefetch(true);
    }
    return pread(fd, buff, size, offset);
}

int file_t::truncate(off_t offset){
    auto_wlock(this);
    size_t newc = GetBlkNo(offset, blksize);
    size_t oldc = GetBlkNo(size, blksize);
    if(newc > oldc){
        for(size_t i = oldc + 1; i<= newc; i++){
            blocks[i] = new block_t(this, "x", i, blksize * i, blksize);
        }
    }
    if(oldc > newc){
        blocks[newc]->prefetch(true);
        for(size_t i = newc + 1; i<= oldc; i++){
            delete blocks[i];
            blocks.erase(i);
        }
        //FIXME: 这里有可能会导致死锁，dirty队列中全部为本文件的block的时候
        blocks[newc]->makedirty();
    }
    size = offset;
    mtime = time(0);
    flags |= FILE_DIRTY;
    assert(fd);
    return TEMP_FAILURE_RETRY(ftruncate(fd, offset));
}

int file_t::write(const void* buff, off_t offset, size_t size) {
    auto_rlock(this);
    if((size_t)offset + size > this->size){
        int ret = truncate(offset + size);
        if(ret < 0){
            return ret;
        }
    }
    size_t startc = GetBlkNo(offset, blksize);
    size_t endc = GetBlkNo(offset + size, blksize);
    for(size_t i = startc; i <= endc; i++){
        blocks[i]->prefetch(true);
    }
    for(size_t i =  startc; i <= endc; i++){
        blocks[i]->makedirty();
    }
    __r.upgrade();
    mtime = time(0);
    flags |= FILE_DIRTY;
    return pwrite(fd, buff, size, offset);
}


int file_t::sync(){
    auto_rlock(this);
    for(auto i: blocks){
        i.second->sync();
    }
    return 0;
}

std::vector<string> file_t::getfblocks(){
    auto_rlock(this);
    std::vector<string> fblocks(blocks.size());
    for(auto i : this->blocks){
        fblocks[i.first] = i.second->getname();
    }
    return fblocks;
}

int file_t::release(){
    auto_rlock(this);
    for(auto i: blocks){
        i.second->reset();
    }
    __r.upgrade();
    if(fd){
        close(fd);
    }
    fd = 0;
    return 0;
}

int file_t::getbuffer(void* buffer, off_t offset, size_t size) {
    auto_rlock(this);
    assert(fd);
    int ret = TEMP_FAILURE_RETRY(pread(fd, buffer, size, offset));
    if(flags & FILE_ENCODE){
        xorcode(buffer, offset, ret, API_AK);
    }
    return ret;
}

int file_t::putbuffer(void* buffer, off_t offset, size_t size) {
    auto_rlock(this);
    assert(fd);
    if(flags & FILE_ENCODE){
        xorcode(buffer, offset, size, API_AK);
    }
    return TEMP_FAILURE_RETRY(pwrite(fd, buffer, size, offset));
}

string file_t::getpath() {
    auto_rlock(this);
    return entry->getpath();
}

void file_t::trim(string name) {
    if(name == "" || name == "x"){
        return;
    }
    auto_lock(&extraLocker);
    droped.insert(name);
}

void file_t::post_sync() {
    wlock();
    flags &= ~FILE_DIRTY;
    unwlock();

    string path = entry->getpath();
    auto_lock(&extraLocker);
    if(droped.empty()){
        return;
    }
    std::set<string> dlist;
    for(auto i: droped){
        dlist.insert(path + "/" + i);
    }
    droped.clear();
    baiduapi_batchdelete(dlist);
}

struct stat file_t::getattr() {
    auto_rlock(this);
    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_ino = flags;
    st.st_size = size;
    st.st_blksize = blksize;
    st.st_blocks = size/512 + 1;
    st.st_mtime = mtime;
    return st;
}

void file_t::setmtime(time_t mtime) {
    auto_wlock(this);
    flags |= FILE_DIRTY;
    this->mtime = mtime;
}
