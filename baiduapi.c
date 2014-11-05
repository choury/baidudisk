#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <fuse.h>


#include <unistd.h>


#include <json/json.h>


#include "json_object_from_file.h"
#include "urlcode.h"
#include "baiduapi.h"
#include "threadpool.h"
#include "cache.h"
#include "net.h"


static const char *basepath = "/apps/Native";
static const char *ak = "iN1yzFR9Sos27UWGEpjvKNVs";
static const char *sk = "wiz77wrFfUGje0oGGOaG3kOU7T18dSg2";


#define Min(x,y)   ((x)<(y)?(x):(y))
#define Max(x,y)   ((x)>(y)?(x):(y))



static char Access_Token[100];



static sem_t wcache;                                     //这个用来计算还有多少写缓存


/*处理百度服务器返回的各种乱七八糟的错误码，转换成errno形式的
 * 只有我经常碰到的错误，并且我能对应得上的一些
 * 如果返回111,即AT过期，则刷新AT
 */
static int handleerror(const int error)
{
    switch (error) {
    case 3:
        errno = ESRCH;
        break;

    case 4:
        errno = EACCES;
        break;

    case 5:
        errno = EPERM;
        break;
    case 111:                               //Access_Token 过期，重新刷新
        refreshtoken();
        errno = EAGAIN;
        break;
    case 31021:
        errno = ENETUNREACH;
        break;

    case 31023:
        errno = EINVAL;
        break;

    case 31061:
        errno = EEXIST;
        break;

    case 31062:
        errno = EBADF;
        break;

    case 31066:
        errno = ENOENT;
        break;

    case 31202:
        errno = ENOENT;
        break;

    default:
        errorlog("No defined errno:%d\n", error);
        errno = EPROTO;
        break;
    }

    return -errno;
}



//顾名思义，将服务器传回的数据写到buff中

static size_t savetobuff(void *buffer, size_t size, size_t nmemb, void *user_p)
{
    buffstruct *bs = (buffstruct *) user_p;
    size_t len = size * nmemb;
    memcpy(bs->buf + bs->offset, buffer, len);
    bs->offset += len;
    return len;
}

//写到文件中
static size_t savetofile(void *buffer, size_t size, size_t nmemb, void *user_p)
{
    FILE *fp = (FILE *) user_p;
    size_t return_size = fwrite(buffer, size, nmemb, fp);
    return return_size;
}


//从文件中读取给服务器发送的程序
static size_t readfromfile(void *buffer, size_t size, size_t nmemb, void *user_p)
{
    FILE *file = (FILE *) user_p;
    return fread(buffer, size, nmemb, file);
}

static size_t readfromfd(void *buffer, size_t size, size_t nmemb, void *user_p)
{
    int fd = (int) (long)user_p;
    return read(fd,buffer, size*nmemb)/size;
}

//你猜
static size_t readfrombuff(void *buffer, size_t size, size_t nmemb, void *user_p)
{
    buffstruct *bs = (buffstruct *) user_p;
    size_t len = Min(size * nmemb, (bs->len) - bs->offset);
    memcpy(buffer, bs->buf + bs->offset, len);
    bs->offset += len;
    return len;
}


typedef struct {
    filedec *fd;
    size_t  bno;
} block;


//从服务器读一个block
int readblock(block *tb)
{
    block b = *tb;
    free(tb);
    size_t startp = b.bno * RBS;
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, b.fd->path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=download&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath));
    char range[100] = {0};
    snprintf(range, sizeof(range) - 1, "%lu-%lu", startp, startp + RBS - 1);
    char buf[RBS];
    buffstruct bs = {0, RBS, buf};
    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    r->method = get;
    r->writefunc = savetobuff;
    r->writeprame = &bs;
    r->range = range;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        Httpdestroy(r);
        return -EPROTO;
    }

    Httpdestroy(r);
    pthread_mutex_lock(&b.fd->lock);
    lseek(b.fd->file, startp, SEEK_SET);
    write(b.fd->file,bs.buf, bs.offset);
    b.fd->cache.r.mask[b.bno / 32] |= 1 << (b.bno % 32);
    pthread_mutex_unlock(&b.fd->lock);
    return bs.offset;
}

//上传一个block作为tmpfile
int uploadblock(block *tb)
{
    block b = *tb;
    free(tb);
    size_t startp = GetWriteBlkStartPoint(b.bno);
    char buff[1024];
    snprintf(buff, sizeof(buff) - 1,
             "https://c.pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "type=tmpfile"
             , Access_Token);

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        CLRT(b.fd->cache.w.flags, b.bno);
        return -lasterrno;
    }

    FILE *tpfile = tmpfile();
    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        CLRT(b.fd->cache.w.flags, b.bno);
        return -lasterrno;
    }

    char *buf = (char *)malloc(GetWriteBlkSize(b.bno));
    buffstruct bs = {0, GetWriteBlkSize(b.bno), buf};
    pthread_mutex_lock(&b.fd->lock);
    lseek(b.fd->file, startp, SEEK_SET);
    bs.len = read(b.fd->file,bs.buf, bs.len);
    CLRR(b.fd->cache.w.flags, b.bno);
    pthread_mutex_unlock(&b.fd->lock);

    r->method = post_formdata;
    r->readfunc = readfrombuff;
    r->readprame = &bs;
    r->length = bs.len;
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        free(buf);
        Httpdestroy(r);
        fclose(tpfile);
        CLRT(b.fd->cache.w.flags, b.bno);
        return -EPROTO;
    }
    free(buf);
    Httpdestroy(r);

    json_object * json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        CLRT(b.fd->cache.w.flags, b.bno);
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        CLRT(b.fd->cache.w.flags, b.bno);
        return handleerror(errorno);
    }

    json_object *jmd5;
    if (json_object_object_get_ex(json_get, "md5",&jmd5)) {
        if (b.bno) {
            sem_post(&wcache);
        }
        pthread_mutex_lock(&b.fd->lock);
        if (GETR(b.fd->cache.w.flags, b.bno)) {
            CLRR(b.fd->cache.w.flags, b.bno);
        } else {
            strcpy(b.fd->cache.w.md5[b.bno], json_object_get_string(jmd5));
            CLRD(b.fd->cache.w.flags, b.bno);
        }
        CLRT(b.fd->cache.w.flags, b.bno);
        pthread_mutex_unlock(&b.fd->lock);
        json_object_put(json_get);
        return bs.offset;
    } else {
        errorlog("Did not get MD5:%s\n", json_object_to_json_string(json_get));
        CLRT(b.fd->cache.w.flags, b.bno);
        return -EPROTO;
    }
}

/* 遍历fcache的处理函数
 * 如果文件已经被释放，则同步该文件
 * 否则：
 * 对于写缓存：已经同步完的block取回结果
 * 写满的脏block，上传该block
 * 对于同步完有段时间的和被标记删除的，则删除该缓存
 */
void handlefcache(filedec *f)
{
    size_t i;
    if (pthread_mutex_trylock(&f->lock) == 0) {
        if (f->flags == 0) {                       //如果该文件未被同步,未在同步，未被标记删除
            if (f->count == 0) {                    //文件已被关闭
                f->flags |= TRANSF;
                addtask((taskfunc)fcachesync, f, 0);
            } else {
                switch (f->type) {
                case forread:
                    break;
                case forwrite:
                    for (i = 0; i < GetWriteBlkNo(f->lengh); ++i) {
                        if (f->cache.w.taskid[i]) {
                            if (GETT(f->cache.w.flags, i) == 0) {
                                waittask(f->cache.w.taskid[i]);                               //如果传送已经结束了就取回结果
                                f->cache.w.taskid[i] = 0;
                            }
                        } else if (GETD(f->cache.w.flags, i)) {              //如果这个block是脏的那么加个上传任务
                            block *b = (block *)malloc(sizeof(block));
                            b->bno = i;
                            b->fd = f;
                            SETT(f->cache.w.flags, i);
                            f->cache.w.taskid[i] = addtask((taskfunc) uploadblock, b, 1);
                        }
                    }
                    break;
                }
            }
        } else if ((f->flags & SYNCED) &&
                   (f->flags & DELETE) == 0 &&
                   time(NULL) - f->rlstime > 60 * 10) {          //同步结束时间超过10分种
            f->flags |= DELETE;
            f->flags |= ONDELE;
            addtask((taskfunc)freefcache, f, 0);                             //释放它
        } else if ((f->flags & DELETE) &&
                   (f->flags & ONDELE) == 0) {                        //删除被标记删除的项
            f->flags |= ONDELE;
            addtask((taskfunc)freefcache, f, 0);
        }
        pthread_mutex_unlock(&f->lock);
    }
}


/* 每隔1s就遍历一遍fcache，根据flag做些操作，这是一个独立的后台线程
 */
static void autosync()
{
    while (1) {
        eachfcache(handlefcache);
        sleep(1);
    }
}

/*获得Access_Token
 * 我曾经把自己模拟成浏览器手动post用户名密码，开始挺好使的
 * 后来不行了……因为登录次数多了居然要输验证码了！！！
 */
int gettoken()
{
    char code[200];
    char buff[1024];
    char ATfile[1024];
    json_object *json_get;

    sprintf(ATfile,"%s/Access_Token",confpath);
    if (!(json_get = json_object_from_file(ATfile))) {                     //如果当前目录下面没有.Access_Token文件，那么重新获取
        fprintf(stderr, "You have to login first!\n");

        if (fork() == 0) {
            snprintf(buff, sizeof(buff) - 1,
                     "x-www-browser "                                               //什么？你说没有x-www-browser？那可不关我的事，你自己搞定吧
                     "-new-tab "
                     "\"http://openapi.baidu.com/oauth/2.0/authorize?"
                     "response_type=code&"
                     "client_id=%s&"
                     "redirect_uri=oob&"
                     "scope=netdisk&"
                     "display=page\""
                     , ak);
            system(buff);
            exit(errno);
        } else {
            puts("please copy the authorization code from the browser:");
            scanf("%199s", code);
            sprintf(buff,
                    "https://openapi.baidu.com/oauth/2.0/token?"
                    "grant_type=authorization_code&"
                    "code=%s&"
                    "client_id=%s&"
                    "client_secret=%s&"
                    "redirect_uri=oob"
                    , code, ak, sk);
            FILE *tpfile = tmpfile();

            if (!tpfile) {
                int lasterrno = errno;
                errorlog("create temp file error:%s\n", strerror(errno));
                return -lasterrno;
            }

            Http *r = Httpinit(buff);

            if (r == NULL) {
                int lasterrno = errno;
                errorlog("can't resolve domain:%s\n", strerror(errno));
                fclose(tpfile);
                return -lasterrno;
            }

            r->method = get;
            r->writefunc = savetofile;
            r->writeprame = tpfile;

            if ((errno = request(r)) != CURLE_OK) {
                errorlog("network error:%d\n", errno);
                fclose(tpfile);
                Httpdestroy(r);
                return -EPROTO;
            }

            Httpdestroy(r);
            json_get = json_object_from_FILE(tpfile);
            fclose(tpfile);

            if (json_get == NULL) {
                errorlog("json_object_from_FILE filed!\n");
                return -EPROTO;
            }

            json_object *jerror_code;
            if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
                int errorno = json_object_get_int(jerror_code) ;
                json_object_put(json_get);
                return handleerror(errorno);
            }

            json_object *jaccess_token;
            if (json_object_object_get_ex(json_get, "access_token",&jaccess_token)) {        //找到access_token了，存到文件里面
                strcpy(Access_Token, json_object_get_string(jaccess_token));
                json_object_to_file(ATfile, json_get);
                json_object_put(json_get);
            } else {
                puts("Authorization error!");
                remove(ATfile);
                json_object_put(json_get);
                errno = EPERM;
                return -errno;
            }
        }

    } else {            //如果文件里面存在，直接读取文件，当然，这里没有考虑有不怀好意的人修改我的文件的情况
        json_object *jaccess_token;
        json_object_object_get_ex(json_get, "access_token",&jaccess_token);
        strcpy(Access_Token, json_object_get_string(jaccess_token));
        json_object_put(json_get);
    }

    return 0;
}

int refreshtoken()
{
    char buff[1024];
    char ATfile[1024];
    char Refresh_Token[100];
    json_object *json_get;

    sprintf(ATfile,"%s/Access_Token",confpath);
    if (!(json_get = json_object_from_file(ATfile))) {            //如果当前目录下面没有.Access_Token文件，那么直接调用gettoken
        return gettoken();
    } else {
        
        json_object *jrefresh_token;
        json_object_object_get_ex(json_get, "refresh_token",&jrefresh_token);
        strcpy(Refresh_Token, json_object_get_string(jrefresh_token));
        json_object_put(json_get);
        snprintf(buff, sizeof(buff) - 1,
                 "https://openapi.baidu.com/oauth/2.0/token?"
                 "grant_type=refresh_token&"
                 "refresh_token=%s&"
                 "client_id=%s&"
                 "client_secret=%s", Refresh_Token, ak, sk);
        FILE *tpfile = tmpfile();

        if (!tpfile) {
            int lasterrno = errno;
            errorlog("create temp file error:%s\n", strerror(errno));
            return -lasterrno;
        }

        Http *r = Httpinit(buff);

        if (r == NULL) {
            int lasterrno = errno;
            errorlog("can't resolve domain:%s\n", strerror(errno));
            fclose(tpfile);
            return -lasterrno;
        }

        r->method = get;
        r->writefunc = savetofile;
        r->writeprame = tpfile;

        if ((errno = request(r)) != CURLE_OK) {
            errorlog("network error:%d\n", errno);
            fclose(tpfile);
            Httpdestroy(r);
            return -EPROTO;
        }

        Httpdestroy(r);
        json_get = json_object_from_FILE(tpfile);
        fclose(tpfile);

        if (json_get == NULL) {
            errorlog("json_object_from_FILE filed!\n");
            return -EPROTO;
        }
        
        json_object *jerror_code;
        if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
            int errorno = json_object_get_int(jerror_code) ;
            json_object_put(json_get);
            return handleerror(errorno);
        }

        json_object *jaccess_token;
        if (json_object_object_get_ex(json_get, "access_token",&jaccess_token)) {              
            //找到access_token了，存到文件里面
            strcpy(Access_Token, json_object_get_string(jaccess_token));
            json_object_to_file(ATfile, json_get);
            json_object_put(json_get);
        } else {
            puts("Authorization error!");
            json_object_put(json_get);
            errno = EPERM;
            return -errno;
        }
    }
    return 0;
}

//初始化，没什么好说的……
void *baiduapi_init(struct fuse_conn_info *conn)
{
    sem_init(&wcache, 0, MAXCACHE);
    initcache();
    creatpool(THREADS);
    pthread_t p;
    
    pthread_create(&p, NULL, (void * ( *)(void *)) autosync, NULL);
    char basedir[PATHLEN];
    sprintf(basedir,"%s/.baidudisk",getenv("HOME"));
    mkdir(basedir,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    return NULL;
}

//获得文件属性……
int baiduapi_getattr(const char *path, struct stat *st)
{
    filedec *f = getfcache(path);

    if (f) {
        if (f->flags & DELETE) {
            pthread_mutex_unlock(&f->lock);
            return -ENOENT;
        } else {
            st->st_size = f->lengh;
            st->st_mode = S_IFREG | 0444;
            pthread_mutex_unlock(&f->lock);
            return 0;
        }
    }

    struct stat *tst = getscache(path);
    if (tst) {
        *st = *tst;
        return 0;
    }
    char buff[2048];
    json_object *json_get = 0, *filenode;
    char fullpath[PATHLEN];
    memset(st, 0, sizeof(struct stat));
    st->st_nlink = 1;
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);

    if (strcmp(path, "/") == 0) {                   //根目录，直接返回，都根目录了，你还查什么查啊，还一直查，说你呢，fuse
        st->st_mode = S_IFDIR | 0755;
        return 0;
    }

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=meta&"
             "access_token=%s&"
             "path=%s",
             Access_Token, URLEncode(fullpath));
    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = get;
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        fclose(tpfile);
        Httpdestroy(r);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        return handleerror(errorno);
    }

    json_object *jlist;
    json_object_object_get_ex(json_get, "list",&jlist);
    filenode = json_object_array_get_idx(jlist, 0);
    
    json_object *jmtime;
    json_object_object_get_ex(filenode, "mtime",&jmtime);
    st->st_mtim.tv_sec = json_object_get_int64(jmtime);
    
    json_object *jctime;
    json_object_object_get_ex(filenode, "ctime",&jctime);
    st->st_ctim.tv_sec = json_object_get_int64(jctime);
    
    json_object *jfs_id;
    json_object_object_get_ex(filenode, "fs_id",&jfs_id);
    st->st_ino = json_object_get_int64(jfs_id);
    
    json_object *jsize;
    json_object_object_get_ex(filenode, "size",&jsize);
    st->st_size = json_object_get_int64(jsize);

    json_object *jisdir;
    json_object_object_get_ex(filenode, "isdir",&jisdir);
    if (json_object_get_boolean(jisdir)) {
        st->st_mode = S_IFDIR | 0755;                        //文件：只读，想要写，对不起，先拷贝一份下来，然后覆盖
    } else {
        st->st_mode = S_IFREG | 0444;
    }
    addscache(path, *st);
    json_object_put(json_get);
    return 0;
}


//读取目录下面有什么文件
int baiduapi_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    (void) fi;

    char buff[2048];
    char fullpath[PATHLEN];
    sprintf(fullpath, "%s%s", basepath, path);
    int pathlen = strlen(fullpath);

    if (fullpath[pathlen - 1] != '/') {         //如果路径不是以‘/’结尾的，加一个‘/’
        fullpath[pathlen] = '/';
        fullpath[++pathlen] = '\0';
    };

    

    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    st.st_nlink = 1;

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=list&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath));

    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = get;
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        fclose(tpfile);
        Httpdestroy(r);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        return handleerror(errorno);
    }

    json_object *jlist;
    json_object_object_get_ex(json_get, "list",&jlist);
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    
    int i;
    for (i = 0; i < json_object_array_length(jlist); ++i) {
        json_object *filenode = json_object_array_get_idx(jlist, i);
        
        json_object *jmtime;
        json_object_object_get_ex(filenode, "mtime",&jmtime);
        st.st_mtim.tv_sec = json_object_get_int64(jmtime);
        
        json_object *jctime;
        json_object_object_get_ex(filenode, "ctime",&jctime);
        st.st_ctim.tv_sec = json_object_get_int64(jctime);
        
        json_object *jfs_id;
        json_object_object_get_ex(filenode, "fs_id",&jfs_id);
        st.st_ino = json_object_get_int64(jfs_id);
        
        json_object *jsize;
        json_object_object_get_ex(filenode, "size",&jsize);
        st.st_size = json_object_get_int64(jsize);

        json_object *jisdir;
        json_object_object_get_ex(filenode, "isdir",&jisdir);
        if (json_object_get_boolean(jisdir)) {
            st.st_mode = S_IFDIR | 0755;
        } else {
            st.st_mode = S_IFREG | 0444;
        }
        
        json_object *jpath;
        json_object_object_get_ex(filenode, "path",&jpath);
        filler(buf, json_object_get_string(jpath) + pathlen, &st, 0);
        addscache(json_object_get_string(jpath) + strlen(basepath), st);
    }

    json_object_put(json_get);

    filldir(path, buf, filler);
    return 0;
}


//获得文件系统信息，对于百度网盘来说，只有容量是有用的……
int baiduapi_statfs(const char *path, struct statvfs *sf)
{
    char buff[1025];
    sprintf(buff,
            "https://pcs.baidu.com/rest/2.0/pcs/quota?"
            "method=info&"
            "access_token=%s", Access_Token);
    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = get;
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n",  errno);
        fclose(tpfile);
        Httpdestroy(r);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        return handleerror(errorno);
    }

    sf->f_bsize = 1;
    sf->f_frsize = 1;
    
    json_object *jquota;
    json_object_object_get_ex(json_get, "quota",&jquota);
    sf->f_blocks = json_object_get_int64(jquota);
    
    json_object *jused;
    json_object_object_get_ex(json_get, "used",&jused);
    sf->f_bavail = sf->f_blocks - json_object_get_int64(jused);
    sf->f_bfree = sf->f_bavail;
    json_object_put(json_get);

    return 0;
}


//自猜
int baiduapi_mkdir(const char *path, mode_t mode)
{
    (void) mode;
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=mkdir&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath));
    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = get;
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        fclose(tpfile);
        Httpdestroy(r);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        return handleerror(errorno);
    }

    json_object_put(json_get);
    return 0;
}


//删除文件（不是文件夹）
int baiduapi_unlink(const char *path)
{
    rmscache(path);
    filedec *f = getfcache(path);

    if (f) {
        f->flags |= DELETE;
        pthread_mutex_unlock(&f->lock);
    }

    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);
    
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=delete&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath));
    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = get;
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        fclose(tpfile);
        Httpdestroy(r);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        errno = handleerror(errorno);
        if (f && errno == -ENOENT) {
            return 0;
        } else {
            return errno;
        }
    }

    json_object_put(json_get);
    return 0;
}

//删除文件夹，会失效所有状态缓存
int baiduapi_rmdir(const char *path)
{
    /*    if(getscache(path))
            return -ENOTEMPTY;
        filedec *f = getcache(path);
        if (f) {
            pthread_mutex_unlock(&f->lock);
            return -ENOTEMPTY;
        }*/


    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=list&"
             "access_token=%s&"
             "path=%s&limit=0-1"
             , Access_Token, URLEncode(fullpath));

    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = get;
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        fclose(tpfile);
        Httpdestroy(r);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        return handleerror(errorno);
    }

    json_object *jlist;
    json_object_object_get_ex(json_get, "list",&jlist);
    if (json_object_array_length(jlist) != 0) {
        json_object_put(json_get);
        return -ENOTEMPTY;
    }
    json_object_put(json_get);

    return baiduapi_unlink(path);
}


int baiduapi_link(const char *target, const char *lnname)
{
    filedec *f = getfcache(target);

    if (f) {
        if ((f->flags & SYNCED) == 0) {                              //如果没有同步则不能操作，其实该文件服务器上还不存在……
            pthread_mutex_unlock(&f->lock);
            return -EBUSY;
        }
        pthread_mutex_unlock(&f->lock);
    }

    char buff[3096];
    char targetfullpath[PATHLEN];
    char lnfullpath[PATHLEN];
    snprintf(targetfullpath, sizeof(targetfullpath) - 1, "%s%s", basepath, target);
    snprintf(lnfullpath, sizeof(lnfullpath) - 1, "%s%s", basepath, lnname);

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=copy&"
             "access_token=%s&"
             "from=%s&"
             "to=%s"
             , Access_Token, URLEncode(targetfullpath), URLEncode(lnfullpath));
    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = get;
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        fclose(tpfile);
        Httpdestroy(r);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        return handleerror(errorno);
    }

    json_object_put(json_get);
    return 0;
}


/* 想猜你就继续猜吧
 */
int baiduapi_rename(const char *oldname, const char *newname)
{
    rmscache(oldname);
    filedec *f = getfcache(oldname);

    if (f) {
        if (f->count != 0) {                                      //如果有没被关闭则不能改名
            pthread_mutex_unlock(&f->lock);
            return -EBUSY;
        }
        if (f->type == forwrite && f->flags == 0) {               //在本地还没有同步，只需要改本地缓存
            renamecache(oldname, newname);
            pthread_mutex_unlock(&f->lock);
            return 0;
        } else if ((f->type == forread) ||                         //读缓存可以直接改
                   (f->type == forwrite && (f->flags & SYNCED))) { //已经同步到服务器，本地缓存和服务器都要改
            renamecache(oldname, newname);
            pthread_mutex_unlock(&f->lock);
        } else {
            pthread_mutex_unlock(&f->lock);
            return -EBUSY;
        }
    }


    char buff[3096];
    char oldfullpath[PATHLEN];
    char newfullpath[PATHLEN];
    snprintf(oldfullpath, sizeof(oldfullpath) - 1, "%s%s", basepath, oldname);
    snprintf(newfullpath, sizeof(newfullpath) - 1, "%s%s", basepath, newname);

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=move&"
             "access_token=%s&"
             "from=%s&"
             "to=%s"
             , Access_Token, URLEncode(oldfullpath), URLEncode(newfullpath));
    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = get;
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        fclose(tpfile);
        Httpdestroy(r);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        return handleerror(errorno);
    }

    json_object_put(json_get);
    return 0;
}


/*
 * 打开一个文件，如果这个文件在缓存里面存在，直接指向它，并将计数器加一
 * 如果只读打开的话，生成一个读缓存文件
 * 如果只写，读写打开，这个文件在服务器上存在的话，不行！
 * 否则，返回文件不存在
 */
int baiduapi_open(const char *path, struct fuse_file_info *fi)
{
    filedec *f = getfcache(path);

    if (f) {
        if ((f->flags & DELETE) ||
                (f->type == forread && (fi->flags & O_ACCMODE) != O_RDONLY)) {
            pthread_mutex_unlock(&f->lock);
            return -EACCES;
        }
        fi->fh = (uint64_t) f;
        f->count++;
        if (f->flags & TRANSF) {
            f->flags |= REOPEN;
        }
        pthread_mutex_unlock(&f->lock);
        return 0;
    }


    struct stat t;
    int ret = baiduapi_getattr(path, &t);

    if (ret == -ENOENT) {
        if (fi->flags & O_CREAT) {                          //如果要求创建文件则调用create
            return baiduapi_create(path, 0, fi);
        } else {                                             //否则返回文件不存在
            return ret;
        }
    } else if ((fi->flags & O_ACCMODE) == O_RDONLY) {
        filedec *f = initfcache(path);

        if (f == NULL) {
            int lasterrno = errno;
            errorlog("Init fcache error:%s\n", strerror(errno));
            return -lasterrno;
        }

        f->type = forread;
        f->count = 1;
        f->lengh = t.st_size;

        fi->fh = (uint64_t) f;
        return 0;
    }

    return -EACCES;
}

/*
 * 释放一个文件
 */
int baiduapi_release(const char *path, struct fuse_file_info *fi)
{
    filedec *f = (filedec *) fi->fh;
    if (f) {
        pthread_mutex_lock(&f->lock);
        f->count--;
        pthread_mutex_unlock(&f->lock);
    }
    return 0;
}


//读
int baiduapi_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    filedec *f = (filedec *) fi->fh;
    int c, ret, i;


    if (offset > f->lengh) {        //如果偏移超过文件长度
        errno = EFAULT;
        return -errno;
    }

    if (offset + size > f->lengh) {   //如果剩余长度不足size，则最多读到文件末尾
        size = f->lengh - offset;
    }

    switch (f->type) {
    case forread:
        c = offset / RBS;  //计算一下在哪个块
        pthread_mutex_lock(&f->lock);
        for (i = 0; i < MAXCACHE; ++i) {             //一般读取的时候绝大部分是向后读，所以缓存下面的几个block
            int p = i + c;
            if (p >= 0 &&
                    p <= f->lengh / RBS &&
                    f->cache.r.taskid[p] == 0 &&
                    !(f->cache.r.mask[p / 32] & (1 << (p % 32)))) {
                block *b = (block *) malloc(sizeof(block));
                b->fd = f;
                b->bno = p;
                f->cache.r.taskid[p] = addtask((taskfunc) readblock, b, 1);
                f->flags &= ~SYNCED;
            }
        }
        pthread_mutex_unlock(&f->lock);
        ret = (long) waittask(f->cache.r.taskid[c]);
        f->cache.r.taskid[c] = 0;
        if (ret < 0) {                                     //读取出错
            return ret;
        }
        pthread_mutex_lock(&f->lock);
        if (!(f->cache.r.mask[c / 32] & (1 << (c % 32)))) {
            pthread_mutex_unlock(&f->lock);
            return -1;                                    //如果在这里返回那么这是一个未知错误，我也不知道发什么了什么
        }
        lseek(f->file, offset, SEEK_SET);
        int len = Min(size, (c + 1) * RBS - offset);      //计算最长能读取的字节
        ret = read(f->file,buf, len);
        pthread_mutex_unlock(&f->lock);

        if (ret != len) {                   //读取出错了
            return ret;
        }

        if (len < size) {                   //需要读取下一个block
            int tmp = baiduapi_read(path, buf + len, size - len, offset + len, fi);
            if (tmp < 0) {                  //调用出错
                return tmp;
            } else
                ret += tmp;
        }

        return ret;                         //成功返回

    case forwrite:

        pthread_mutex_lock(&f->lock);
        lseek(f->file, offset, SEEK_SET);
        ret = read(f->file,buf, size);
        pthread_mutex_unlock(&f->lock);

        return ret;
    }

    errno = EPERM;
    return -errno;
}


//上传一个文件
int baiduapi_uploadfile(int file, const char *path)
{
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath)-1, "%s%s", basepath, path);
    snprintf(buff, sizeof(buff) - 1,
             "https://c.pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "path=%s&"
             "ondup=overwrite"
             , Access_Token, URLEncode(fullpath));

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    FILE *tpfile = tmpfile();
    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    r->method = post_formdata;
    r->readfunc = readfromfd;
    r->readprame = (void *)(long)file;
    r->length = lseek(file, 0, SEEK_END);
    lseek(file, 0, SEEK_SET);
    r->writefunc = savetofile;
    r->writeprame = tpfile;
    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        Httpdestroy(r);
        fclose(tpfile);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get= json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        return handleerror(errorno);
    }

    json_object *jmd5;
    if (json_object_object_get_ex(json_get, "md5",&jmd5)) {
        json_object_put(json_get);
        return 0;
    } else {
        errorlog("Did not get MD5:%s\n" , json_object_to_json_string(json_get));
        json_object_put(json_get);
        return -EPROTO;
    }
}


//上传一个临时文件，md5是服务器返回的md5值，用来合并成一个文件
int baiduapi_uploadtmpfile(int file, char *md5)
{
    char buff[1024];
    snprintf(buff, sizeof(buff) - 1,
             "https://c.pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "type=tmpfile"
             , Access_Token);
    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = post_formdata;
    r->readfunc = readfromfd;
    r->readprame = (void *)(long)file;
    r->length = lseek(file, 0, SEEK_END);
    lseek(file, 0, SEEK_SET);
    r->writefunc = savetofile;
    r->writeprame = tpfile;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        Httpdestroy(r);
        fclose(tpfile);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
        return handleerror(errorno);
    }

    json_object *jmd5;
    if (json_object_object_get_ex(json_get, "md5",&jmd5)) {
        strcpy(md5, json_object_get_string(jmd5));
        json_object_put(json_get);
        return 0;
    } else {
        errorlog("Did not get MD5:%s\n", json_object_to_json_string(json_get));
        return -EPROTO;
    }
}


//把上传的临时文件合并成一个文件
int baiduapi_mergertmpfile(const char *path, filedec *f)
{
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=createsuperfile&"
             "access_token=%s&"
             "path=%s&"
             "ondup=overwrite"
             , Access_Token, URLEncode(fullpath));
    FILE *tpfile = tmpfile();

    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }

    json_object *jobj = json_object_new_object();
    json_object *jarray = json_object_new_array();

    int i;
    for (i = 0; i <= GetWriteBlkNo(f->lengh); ++i) {
        json_object_array_add(jarray, json_object_new_string(f->cache.w.md5[i]));
    };

    json_object_object_add(jobj, "block_list", jarray);
    char param[35000];
    snprintf(param, sizeof(param) - 1, "param=%s", json_object_to_json_string(jobj));
    json_object_put(jobj);
    buffstruct bs = {0, strlen(param), param};
    bs.len = strlen(bs.buf);
    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        fclose(tpfile);
        return -lasterrno;
    }

    r->method = post_x_www_form_urlencoded;
    r->readfunc = readfrombuff;
    r->readprame = &bs;
    r->writefunc = savetofile;
    r->writeprame = tpfile;
    r->length = bs.len;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        Httpdestroy(r);
        fclose(tpfile);
        return -EPROTO;
    }

    Httpdestroy(r);
    json_object *json_get = json_object_from_FILE(tpfile);
    fclose(tpfile);

    if (json_get == NULL) {
        errorlog("json_object_from_FILE filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        errorlog("body:\n%s\nget:\n%s\n", param, json_object_to_json_string(json_get));
        json_object_put(json_get);
        return handleerror(errorno);
    }

    json_object_put(json_get);
    return 0;
}

//创建一个文件，并把它加到filelist里面
int baiduapi_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    (void) mode;
    filedec *f = initfcache(path);
    if (f == NULL) {
        int lasterrno = errno;
        errorlog("Init fcache error:%s\n", strerror(errno));
        return -lasterrno;
    }

    

    f->type = forwrite;
    f->count = 1;
    SETD(f->cache.w.flags, 0);

    fi->fh = (uint64_t) f;
    return 0;
}


/*
 * 同步一个文件，如果flag被置位的话就等直到这些文件真的被同步成功
 * 否则只是添加一个任务，然后结果什么样就不管了
 * 说实话，我并不知道这个flag原来实际上是什么用……
 */
int baiduapi_fsync(const char *path, int flag, struct fuse_file_info *fi)
{
    if (fi->fh) {
        int i ;
        filedec *f = (filedec *) fi->fh;

        switch (f->type) {

        case forread:
            break;

        case forwrite:
            if (flag) {
                pthread_mutex_lock(&f->lock);
                for (i = 0; i <= GetWriteBlkNo(f->lengh); ++i) {
                    if ((f->cache.w.taskid[i] == 0) && GETD(f->cache.w.flags, i)) {
                        block *b = malloc(sizeof(block));
                        b->bno = i;
                        b->fd = f;
                        SETT(f->cache.w.flags, i);
//                        f->cache.w.trans[i / 32] |= (1 << (i % 32));
                        f->cache.w.taskid[i] = addtask((taskfunc) uploadblock, b, 1);
                    }
                };
                pthread_mutex_unlock(&f->lock);
                int fail = 1;
                while (fail) {
                    fail = 0;
                    for (i = 0; i <= GetWriteBlkNo(f->lengh); ++i) {
                        if (f->cache.w.taskid[i]) {
                            waittask(f->cache.w.taskid[i]);
                            f->cache.w.taskid[i] = 0;
                        }
                        if (GETD(f->cache.w.flags, i)) {
                            pthread_mutex_lock(&f->lock);
                            block *b = malloc(sizeof(block));
                            b->bno = i;
                            b->fd =  f;
                            SETT(f->cache.w.flags, i);
//                            f->cache.w.trans[i / 32] |= (1 << (i % 32));
                            f->cache.w.taskid[i] = addtask((taskfunc) uploadblock, b, 1);
                            pthread_mutex_unlock(&f->lock);
                            fail = 1;
                        }
                    };

                }
            } else {
                pthread_mutex_lock(&f->lock);
                for (i = 0; i < GetWriteBlkNo(f->lengh); ++i) {
                    if ((f->cache.w.taskid[i] == 0) && GETD(f->cache.w.flags, i)) {
                        block *b = malloc(sizeof(block));
                        b->bno = i;
                        b->fd = f;
                        SETT(f->cache.w.flags, i);
//                        f->cache.w.trans[i / 32] |= (1 << (i % 32));
                        f->cache.w.taskid[i] = addtask((taskfunc) uploadblock, b, 1);
                    }
                }
                pthread_mutex_unlock(&f->lock);
            }
            break;
        }
    }

    return 0;
}



/*
 * 写文件，只有本地的文件才可以写，已经传到服务器上的就不能写了
 *
 */
int baiduapi_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{

    filedec *f = (filedec *) fi->fh;
    int c = GetWriteBlkNo(offset);   //计算一下在哪个块
    int len = Min(size, GetWriteBlkEndPointFromP(offset) - offset);      //计算最长能写入的字节
    switch (f->type) {

    case forread:
        errno = EBADF;
        return -EBADF;

    case forwrite:
        if (GETD(f->cache.w.flags, c) == 0) {
            sem_wait(&wcache);                                           //不能有太多的block没有同步
        }
        waittask(f->cache.w.taskid[c]);
        pthread_mutex_lock(&f->lock);
        f->cache.w.taskid[c] = 0;
        f->flags &= ~SYNCED;
        lseek(f->file, offset, SEEK_SET);
        size_t ret = write(f->file,buf, len);
        SETD(f->cache.w.flags, c);
        if (GETT(f->cache.w.flags, c)) {
            SETR(f->cache.w.flags, c);
        }
        pthread_mutex_unlock(&f->lock);

        if (ret != len) {                   //写入出错
            return ret;
        }

        if (ret + offset > f->lengh) {      //文件长度被扩展
            f->lengh = ret + offset;
        }

        if (len < size) {                   //需要写入下一个block
            int tmp = baiduapi_write(path, buf + len, size - len, offset + len, fi);
            if (tmp < 0) {                  //调用出错
                return tmp;
            } else ret += tmp;
        }

        return ret;
    }

    errno = EPERM;
    return -errno;
}



int baiduapi_access(const char *path, int mask)
{
    return 0;
}

int baiduapi_utimens(const char *path, const struct timespec ts[2])
{
    return 0;
}


