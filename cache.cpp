#include <pthread.h>
#include <unordered_map>
#include <fuse.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include "cache.h"
#include "baiduapi.h"


using namespace std;
static unordered_map <string, filedec *> filecache;
static unordered_map <string, struct stat>scache;
static pthread_mutex_t flock;
static pthread_mutex_t slock;

/*
 * 小函数，判断一个文件（不能是目录）被不被一个目录直接包含
 * 比如 /a/b/ /a/b/c 返回1
 * (/a/b/ , /a/c/d)和(/a/b/,/a/b/c/d)都返回0
 * 用来给filldir用的，看缓存中文件有没有自己目录下面的
 */

static int inline isindir(const char *dirpath, const char *path)
{
    int i;
    size_t len = strlen(dirpath);
    if (dirpath[len - 1] == '/') {
        --len;
    };

    for (i = strlen(path) - 1; (i >= 0) && (path[i] != '/'); --i);          //找到它的直接父目录

    return (len == i) && (strncmp(dirpath, path, i) == 0);
}

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


//初始化缓存系统
void initcache()
{
    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,       //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&flock, &mutexattr);
    pthread_mutex_init(&slock, &mutexattr);
    pthread_mutexattr_destroy(&mutexattr);
}

//获得一个初始化好的fcache,如果创建成功，此fcache 会被自动加入缓存中
filedec *initfcache(const char *path)
{
    filedec *f = new filedec;
    if (f == NULL) {
        return NULL;
    }
    memset(f, 0, sizeof(filedec));
    strncpy(f->path, path, PATHLEN);

    pthread_mutexattr_t mutexattr;
    pthread_mutexattr_init(&mutexattr);
    pthread_mutexattr_settype(&mutexattr,        //让它可以递归加锁
                              PTHREAD_MUTEX_RECURSIVE_NP);
    pthread_mutex_init(&f->lock, &mutexattr);    //每个临时文件都有一把锁，操作它时如果不能确定没有其他线程也操作它就应该上锁，好多锁啊，真头疼

    pthread_mutexattr_destroy(&mutexattr);

    f->file = tempfile();

    if (f->file == -1) {
        int lasterrno = errno;
        free(f);
        errno = lasterrno;
        return NULL;
    }
    addfcache(f);
    return f;
}



/* 同步一个文件实际操作函数，
 * 对于读缓存，则取回所有没有取回的readblock结果
 * 对于写缓存，则将该文件同步到服务器
 * 如果该文件正在被同步，其他线程打开文件时会设置REOPEN标志位
 * 这个标志位被设，则同步结束以后不把该文件标志为已同步的，即不设SYNCED标志
 */
void fcachesync(filedec *f)
{
    switch (f->type) {
    case filedec::forread:
        for (size_t i = 0; i <= GetWriteBlkNo(f->lengh); ++i) {
            if (f->cache.r.taskid[i]) {
                waittask(f->cache.r.taskid[i]);
                f->cache.r.taskid[i] = 0;
            }
        }
        pthread_mutex_lock(&f->lock);
        if (f->flags & REOPEN) {
            f->flags &= ~REOPEN;
        } else {
            f->flags |= SYNCED;
            time(&f->rlstime);
        }
        break;
    case filedec::forwrite:
        waittask(f->cache.w.taskid[0]);
        if (f->lengh < LWBS && GETD(f->cache.w.flags, 0)) {                      //小文件，即只有一个block，直接上传
            pthread_mutex_lock(&f->lock);
            if ((f->flags & DELETE) == 0 && (f->flags & REOPEN) == 0) {
                while (baiduapi_uploadfile(f->file, f->path));
                CLRD(f->cache.w.flags, 0);
                f->flags |= SYNCED;
                time(&f->rlstime);
            } else if (f->flags & REOPEN) {
                f->flags &= ~REOPEN;
            } else {
                f->flags |= SYNCED;
            }
        } else {
            struct fuse_file_info fi;
            fi.fh = (uint64_t)f;
            baiduapi_fsync(f->path, 1, &fi);                   //强制sysnc
            pthread_mutex_lock(&f->lock);
            if ((f->flags & DELETE) == 0 && (f->flags & REOPEN) == 0) {
                while (baiduapi_mergertmpfile(f->path, f));
                f->flags |= SYNCED;
                time(&f->rlstime);
            } else if (f->flags & REOPEN) {
                f->flags &= ~REOPEN;
            } else {
                f->flags |= SYNCED;
            }
        }
        break;
    }
    f->flags &= ~TRANSF;
    pthread_mutex_unlock(&f->lock);
}




/* 释放filedec结构体，并从缓存中删除，必须没有被打开，
 * 且没有在同步，即TRANSF标志未置位
 * 否则直接取消ONDELE标志并返回，什么都不干
 * 调用时如果该文件未同步就调用fsync_real先同步
 * 成功返回0
 */
int freefcache(filedec *f)
{
    if (pthread_mutex_trylock(&f->lock) == 0) {
        if (f->count == 0 &&
                (f->flags & TRANSF) == 0) {
            rmfcache(f->path);
            f->flags |= DELETE;
            if ((f->flags & (SYNCED | TRANSF)) == 0) {
                fcachesync(f);
            }
            pthread_mutex_destroy(&f->lock);
            close(f->file);
            delete f;
            return 0;
        } else {
            f->flags &= ~ONDELE;
        }
        pthread_mutex_unlock(&f->lock);
    }
    return 1;
}


//添加一条文件缓存，如果缓存已经超过500了，那么随机吧已同步的删除一个
void addfcache(filedec *f)
{
    pthread_mutex_lock(&flock);
    filecache[f->path] = f;
    if (filecache.size() > 500) {
        for (auto i : filecache) {
            filedec *tf = i.second;
            if ((tf->flags & SYNCED) &&
                    (tf->flags & DELETE) == 0) {          //随机删除一个
                if(freefcache(tf)==0)
                    break;
                else
                    continue;
            }
        }
    }
    pthread_mutex_unlock(&flock);
}

void addscache(const char *path, struct stat st)
{
    pthread_mutex_lock(&slock);
    scache[path] = st;
    pthread_mutex_unlock(&slock);
}

filedec *getfcache(const char *path)
{
    filedec *f;
    pthread_mutex_lock(&flock);
    auto t = filecache.find(path);
    if (t == filecache.end()) {
        f = nullptr;
    } else {
        f = t->second;
        pthread_mutex_lock(&f->lock);
    }
    pthread_mutex_unlock(&flock);
    return f;
}

struct stat *getscache(const char *path)
{
    struct stat *st;
    pthread_mutex_lock(&slock);
    auto t = scache.find(path);
    if (t == scache.end()) {
        st = nullptr;
    } else {
        st = &t->second;
    }
    pthread_mutex_unlock(&slock);
    return st;
}

void rmfcache(const char *path)
{
    pthread_mutex_lock(&flock);
    filecache.erase(path);
    pthread_mutex_unlock(&flock);
}

void rmscache(const char *path)
{
    pthread_mutex_lock(&slock);
    scache.erase(path);
    pthread_mutex_unlock(&slock);
}

void clearscache()
{
    pthread_mutex_lock(&slock);
    scache.clear();
    pthread_mutex_unlock(&slock);
}

void renamecache(const char *oldname, const char *newname)
{
    pthread_mutex_lock(&flock);
    filecache[newname] = filecache[oldname];
    filecache.erase(oldname);
    filedec *f = filecache[newname];
    strncpy(f->path, newname, PATHLEN);
    pthread_mutex_unlock(&flock);
}

void eachfcache(eachfunc func)
{
    pthread_mutex_lock(&flock);
    for (auto i : filecache) {
        func(i.second);
    }
    pthread_mutex_unlock(&flock);
}

void filldir(const char *path, void *buf, fuse_fill_dir_t filler)
{
    struct stat st;
    pthread_mutex_lock(&flock);
    for (auto i : filecache) {
        filedec *f = i.second;
        if (f->type == filedec::forwrite &&
                (f->flags & SYNCED) == 0 &&
                (f->flags & DELETE) == 0 &&
                isindir(path, f->path)) {
            st.st_size = f->lengh;
            st.st_mode = S_IFREG | 0444;
            filler(buf, f->path + strlen(path), &st, 0);
        }
    }
    pthread_mutex_unlock(&flock);

}


