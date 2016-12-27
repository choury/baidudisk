#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <assert.h>
#include <fuse.h>


#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include <json-c/json.h>


#include "json_object_from_file.h"
#include "urlcode.h"
#include "baiduapi.h"
#include "threadpool.h"
#include "cache.h"
#include "net.h"
#include "job.h"


static const char *basepath = "/apps/Native";
static const char *ak = "iN1yzFR9Sos27UWGEpjvKNVs";
static const char *sk = "wiz77wrFfUGje0oGGOaG3kOU7T18dSg2";


#define Min(x,y)   ((x)<(y)?(x):(y))
#define Max(x,y)   ((x)>(y)?(x):(y))



static char Access_Token[100];



static sem_t wcache_sem;                                     //这个用来计算还有多少写缓存


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

    case 31243:
        errno = ETIMEDOUT;
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

void job_handle(){
    while(true){
        uint32_t t = do_job();
        sleep(t>30?30:t);
    }
}


typedef struct {
    inode_t *node;
    size_t  bno;
} block;


//从服务器读一个block
void readblock(block *tb)
{
    block b = *tb;
    free(tb);
    size_t startp = b.bno * RBS;
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, b.node->getcwd().c_str());
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
        errorlog("can't resolve domain:%s\n", strerror(errno));
        goto error;
    }

    r->method = Httprequest::get;
    r->writefunc = savetobuff;
    r->writeprame = &bs;
    r->range = range;

    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        Httpdestroy(r);
        goto error;
    }

    Httpdestroy(r);
    b.node->lockdate();
    pwrite(b.node->rcache->fd, bs.buf, bs.offset, startp);
    b.node->rcache->mask[b.bno / 32] |= 1 << (b.bno % 32);
    b.node->rcache->taskid[b.bno] = 0;
    b.node->unlockdate();
    return;
error:
    b.node->lockdate();
    b.node->rcache->taskid[b.bno] = 0;
    b.node->unlockdate();
}

//上传一个block作为tmpfile
void uploadblock(block *tb)
{
    block b = *tb;
    free(tb);
    char buff[1024];
    snprintf(buff, sizeof(buff) - 1,
             "https://c.pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "type=tmpfile"
             , Access_Token);


    do{
        Http *r = Httpinit(buff);

        if (r == NULL) {
            errorlog("can't resolve domain:%s\n", strerror(errno));
            break;
        }

        FILE *tpfile = tmpfile();
        if (!tpfile) {
            errorlog("create temp file error:%s\n", strerror(errno));
            break;
        }

        char *buf = (char *)malloc(GetWriteBlkSize(b.bno));
        buffstruct bs = {0, GetWriteBlkSize(b.bno), buf};
        b.node->lockdate();
        b.node->wcache->flags[b.bno] |= WF_TRANS;
        bs.len = pread(b.node->wcache->fd, bs.buf, bs.len, GetWriteBlkStartPoint(b.bno));
        b.node->unlockdate();

        r->method = Httprequest::post_formdata;
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
            break;
        }
        free(buf);
        Httpdestroy(r);

        json_object * json_get = json_object_from_FILE(tpfile);
        fclose(tpfile);

        if (json_get == NULL) {
            errorlog("json_object_from_FILE filed!\n");
            break;
        }

        json_object *jerror_code;
        if (json_object_object_get_ex(json_get, "error_code", &jerror_code)) {
            json_object *jerror_msg;
            json_object_object_get_ex(json_get, "error_msg", &jerror_msg);
            errorlog("api error:%s\n", json_object_get_string(jerror_msg));
            json_object_put(json_get);
            break;
        }

        json_object *jmd5;
        if (json_object_object_get_ex(json_get, "md5",&jmd5)) {
            b.node->lockdate();
            b.node->wcache->flags[b.bno] &= ~WF_TRANS;
            if (b.node->wcache->flags[b.bno] & WF_REOPEN) {
                b.node->wcache->flags[b.bno] &= ~WF_REOPEN;
            } else {
                strcpy(b.node->wcache->md5[b.bno], json_object_get_string(jmd5));
                b.node->wcache->flags[b.bno] &= ~WF_DIRTY;
                if (b.bno)
                    sem_post(&wcache_sem);
            }
            b.node->wcache->taskid[b.bno] = 0;
            b.node->unlockdate();
            json_object_put(json_get);
            return;
        } else {
            errorlog("Did not get MD5:%s\n", json_object_to_json_string(json_get));
        }
    }while(0);
    b.node->lockdate();
    b.node->wcache->taskid[b.bno] = 0;
    b.node->unlockdate();
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

        printf("http://openapi.baidu.com/oauth/2.0/authorize?"
               "response_type=code&"
               "client_id=%s&"
               "redirect_uri=oob&"
               "scope=netdisk&"
               "display=page\n", ak);
        puts("please open the url above,and copy the authorization code from the browser:");
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

        r->method = Httprequest::get;
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
        if (json_object_object_get_ex(json_get, "error_code",&jerror_code))
        {
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

        r->method = Httprequest::get;
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
    sem_init(&wcache_sem, 0, MAXCACHE/2);
    creatpool(THREADS);
    char basedir[PATHLEN];
    sprintf(basedir,"%s/.baidudisk",getenv("HOME"));
    mkdir(basedir,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    addtask((taskfunc)job_handle, nullptr, 0);
    return NULL;
}

//获得文件属性……
int baiduapi_getattr(const char *path, struct stat *st) {
    if (strcmp(path, "/") == 0) {                   //根目录，直接返回，都根目录了，你还查什么查啊，还一直查，说你呢，fuse
        st->st_mode = S_IFDIR | 0755;
        return 0;
    }
    
    *st = getstat(path);
    if (st->st_ino) {
        if(st->st_mode == 0){
            return -ENOENT;
        }else{
            return 0;
        }
    }
    char buff[2048];
    json_object *json_get = 0, *filenode;
    char fullpath[PATHLEN];
    memset(st, 0, sizeof(struct stat));
    st->st_nlink = 1;
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);

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

    r->method = Httprequest::get;
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
    st->st_mtime = json_object_get_int64(jmtime);
    
    json_object *jctime;
    json_object_object_get_ex(filenode, "ctime",&jctime);
    st->st_ctime = json_object_get_int64(jctime);
    
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
    json_object_put(json_get);
    inode_t *node = getnode(dirname(path).c_str(), false);
    node->add_cache(basename(path), *st);
    node->unlockmeta();
    return 0;
}

//读取目录下面有什么文件
int baiduapi_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    inode_t* node = getnode(path, true);
    assert(node->type == cache_type::status);
    if(node->filldir(buf, filler)){
        node->unlockmeta();
        return 0;
    }
    node->unlockmeta();

    char buff[2048];
    char fullpath[PATHLEN];
    int pathlen = sprintf(fullpath, "%s%s", basepath, path);
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

    r->method = Httprequest::get;
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
    
    node->lockmeta();
    node->clear_cache();
    for (int i = 0; i < json_object_array_length(jlist); ++i) {
        json_object *filenode = json_object_array_get_idx(jlist, i);
        
        json_object *jmtime;
        json_object_object_get_ex(filenode, "mtime",&jmtime);
        st.st_mtime = json_object_get_int64(jmtime);
        
        json_object *jctime;
        json_object_object_get_ex(filenode, "ctime",&jctime);
        st.st_ctime = json_object_get_int64(jctime);
        
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
        const char *childname = json_object_get_string(jpath) + pathlen;
        filler(buf, childname, &st, 0);
        node->add_cache(childname, st);
    }
    node->flag |= SYNCED;
    node->unlockmeta();

    json_object_put(json_get);
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

    r->method = Httprequest::get;
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
int baiduapi_mkdir(const char *path, mode_t mode) {
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

    r->method = Httprequest::get;
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

    inode_t *node = getnode(dirname(path).c_str(), false);
    struct stat st;
    memset(&st, 0, sizeof(st));
    json_object *jfs_id;
    json_object_object_get_ex(json_get, "fs_id",&jfs_id);
    st.st_ino = json_object_get_int64(jfs_id);
    
    json_object *jmtime;
    json_object_object_get_ex(json_get, "mtime",&jmtime);
    st.st_mtime = json_object_get_int64(jmtime);
    
    json_object *jctime;
    json_object_object_get_ex(json_get, "ctime",&jctime);
    st.st_ctime = json_object_get_int64(jctime);
    
    st.st_mode = S_IFDIR | 0755;
    json_object_put(json_get);
    node->add_cache(basename(path), st);
    node->unlockmeta();
    return 0;
}


//删除文件（不是文件夹）
int baiduapi_unlink(const char *path) {
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

    r->method = Httprequest::get;
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
        if (errno == -ENOENT && rmcache(path) ) {
            return 0;
        } else {
            return errno;
        }
    }

    json_object_put(json_get);
    rmcache(path);
    return 0;
}

//删除文件夹
int baiduapi_rmdir(const char *path) {
    inode_t* node = getnode(path, false);
    if(node){
        if(node->flag & SYNCED){
            assert(node->type == cache_type::status);
            if(!node->empty()){
                node->unlockmeta();
                return -ENOTEMPTY;
            }
        }
        node->unlockmeta();
    }else{
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

        r->method = Httprequest::get;
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
    }

    return baiduapi_unlink(path);
}


/* 想猜你就继续猜吧
 */
int baiduapi_rename(const char *oldname, const char *newname) {
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

    r->method = Httprequest::get;
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
    renamecache(oldname, newname);
    return 0;
}

//创建一个文件，并把它加到filelist里面
int baiduapi_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) mode;
    inode_t *node = getnode(path, true);
    assert(node->type == cache_type::status);
    assert(node->opened == 0);
    assert(node->wcache == nullptr && node->rcache == nullptr);
    
    node->wcache = new wfcache();
    node->type = cache_type::write;
    node->opened = 1;
    
    node->st.st_ino  = 1;
    node->st.st_nlink = 1;
    node->st.st_size = 0;
    node->st.st_mode = S_IFREG | 0666;
    node->st.st_ctime = time(NULL);
    node->st.st_mtime = time(NULL);
    node->wcache->flags[0] = WF_DIRTY;

    fi->fh = (uint64_t) node;
    node->unlockmeta();
    return 0;
}


/*
 * 打开一个文件，如果这个文件在缓存里面存在，直接指向它，并将计数器加一
 * 如果只读打开的话，生成一个读缓存文件
 * 如果只写，读写打开，这个文件在服务器上存在的话，不行！
 * 否则，返回文件不存在
 */
int baiduapi_open(const char *path, struct fuse_file_info *fi) {
    struct stat st;
    inode_t* node = getnode(path, false);
    if (node) {
        switch(node->type){
        case cache_type::read:
            if((fi->flags & O_ACCMODE) != O_RDONLY) {
                node->unlockmeta();
                return -EACCES;
            }
        case cache_type::write:
            fi->fh = (uint64_t) node;
            node->opened++;
            node->unlockmeta();
            return 0;
        case cache_type::status:
            st = node->st;
            node->unlockmeta();
        }
    }else{
        int ret = baiduapi_getattr(path, &st);
        if (ret < 0) {
            return ret;
        }
    }
    if ((fi->flags & O_ACCMODE) == O_RDONLY) {
        inode_t *node = getnode(path, true);
        assert(node->type == cache_type::status);
        assert(node->opened == 0);
        assert(node->wcache == nullptr && node->rcache == nullptr);
        
        node->rcache = new rfcache();
        node->type = cache_type::read;
        node->opened = 1;
        node->st  = st;
        fi->fh = (uint64_t) node;
        node->unlockmeta();
        return 0;
    }
    return -EACCES;
}

/*
 * 释放一个文件
 */
int baiduapi_release(const char *path, struct fuse_file_info *fi)
{
    inode_t *node = (inode_t*) fi->fh;
    node->release();
    return 0;
}


//读
int baiduapi_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    inode_t *node = (inode_t *) fi->fh;
    node->lockmeta();
    assert(node->type != cache_type::status);
    if (offset > node->st.st_size) {        //如果偏移超过文件长度
        node->unlockmeta();
        errno = EFAULT;
        return -errno;
    }

    if (offset + size > (size_t)node->st.st_size) {   //如果剩余长度不足size，则最多读到文件末尾
        size = node->st.st_size - offset;
    }
    if(node->type ==  cache_type::read){
        node->lockdate();
        int c = offset / RBS;  //计算一下在哪个块
        for (int i = 0; i < MAXCACHE/2; ++i) {             //一般读取的时候绝大部分是向后读，所以缓存下面的几个block
            size_t p = i + c;
            if (p <= node->st.st_size / RBS &&
                node->rcache->taskid[p] == 0 &&
                !(node->rcache->mask[p / 32] & (1 << (p % 32))))
            {
                block *b = (block *) malloc(sizeof(block));
                b->node = node;
                b->bno = p;
                node->rcache->taskid[p] = addtask((taskfunc) readblock, b, 0);
                node->flag &= ~SYNCED;
            }
        }
        node->unlockdate();
        node->unlockmeta();
        waittask(node->rcache->taskid[c]);
        node->lockdate();
        if (!(node->rcache->mask[c / 32] & (1 << (c % 32)))) {
            node->unlockdate();
            return -EIO;                                    //如果在这里返回那么读取出错
        }
        size_t len = Min(size, (c + 1) * RBS - offset);      //计算最长能读取的字节
        ssize_t ret = pread(node->rcache->fd, buf, len, offset);
        node->unlockdate();
        if (ret != (ssize_t)len) {                   //读取出错了
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
    }else{
        node->lockdate();
        ssize_t ret = pread(node->wcache->fd,buf, size, offset);
        node->unlockdate();
        node->unlockmeta();
        return ret;
    }
}


//上传一个文件
int baiduapi_uploadfile(int file, const char *path) {
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

    r->method = Httprequest::post_formdata;
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
        errorlog("get error:%s\n", json_object_to_json_string(json_get));
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


//把上传的临时文件合并成一个文件
int baiduapi_mergertmpfile(const char *path, inode_t *node) {
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

    json_object *jobj = json_object_new_object();
    json_object *jarray = json_object_new_array();

    for (size_t i = 0; i <= GetWriteBlkNo(node->st.st_size); ++i) {
        json_object_array_add(jarray, json_object_new_string(node->wcache->md5[i]));
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
        return -lasterrno;
    }

    FILE *tpfile = tmpfile();
    if (!tpfile) {
        int lasterrno = errno;
        errorlog("create temp file error:%s\n", strerror(errno));
        return -lasterrno;
    }
    r->method = Httprequest::post_x_www_form_urlencoded;
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



/*
 * 同步一个文件，如果flag被置位的话就等直到这些文件真的被同步成功
 * 否则只是添加一个任务，然后结果什么样就不管了
 * 说实话，我并不知道这个flag原来实际上是什么用……
 */
int filesync(inode_t *node){
    node->lockmeta();
    if(node->flag & SYNCED){
        node->unlockmeta();
        return 0;
    }
    node->lockdate();
    switch (node->type) {
    case cache_type::read:
        for (size_t i = 0; i <= GetWriteBlkNo(node->st.st_size); ++i) {
            if (node->rcache->taskid[i]) {
                node->unlockdate();
                waittask(node->rcache->taskid[i]);
                node->lockdate();
            }
        }
        break;
    case cache_type::write:
        if ((size_t)node->st.st_size < LWBS) {
            while (baiduapi_uploadfile(node->wcache->fd, node->getcwd().c_str()));
            node->wcache->flags[0] = 0;
            time(&node->st.st_mtime);
        } else {
            int done = 0;
            while (!done) {
                done = 1;
                for (size_t i = 0; i <= GetWriteBlkNo(node->st.st_size); ++i) {
                    if (node->wcache->taskid[i]) {
                        node->unlockdate();
                        waittask(node->wcache->taskid[i]);
                        node->lockdate();
                    }
                    if (node->st.st_nlink && (node->wcache->flags[i] & WF_DIRTY)) {
                        block *b = (block *)malloc(sizeof(block));
                        b->bno = i;
                        b->node =  node;
                        node->wcache->taskid[i] = addtask((taskfunc) uploadblock, b, 0);
                        done = 0;
                    }
                }
            }
            while (baiduapi_mergertmpfile(node->getcwd().c_str(), node));
            time(&node->st.st_mtime);
        }
        break;
    case cache_type::status:
        assert(0);
    }
    node->unlockdate();
    node->flag |= SYNCED;
    node->unlockmeta();
    return 0;
}

int baiduapi_fsync(const char *, int , struct fuse_file_info *fi) {
    inode_t *node = (inode_t *) fi->fh;
    return filesync(node);
}


int baiduapi_flush(const char * path, struct fuse_file_info *fi){
    return baiduapi_fsync(path, 0, fi);
}
/*
 * 写文件，只有本地的文件才可以写，已经传到服务器上的就不能写了
 *
 */
int baiduapi_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    inode_t* node = (inode_t *) fi->fh;
    int c = GetWriteBlkNo(offset);   //计算一下在哪个块
    int len = Min(size, GetWriteBlkEndPointFromP(offset) - offset);      //计算最长能写入的字节
    node->lockmeta();
    if(node->type == cache_type::write) {
        if(offset > node->st.st_size) {
            baiduapi_truncate(path, offset);
        }
        if (c && (node->wcache->flags[c] & WF_DIRTY) == 0) {
            node->unlockmeta();
            sem_wait(&wcache_sem);                                           //不能有太多的block没有同步
            node->lockmeta();
        }
        node->flag &= ~SYNCED;
        node->lockdate();
        ssize_t ret = pwrite(node->wcache->fd,buf, len, offset);
        
        if (ret + offset > node->st.st_size) {      //文件长度被扩展
            node->st.st_size = ret + offset;
        }
        
        node->wcache->flags[c] |= WF_DIRTY;
        if (node->wcache->flags[c] & WF_TRANS) {
            node->wcache->flags[c] |= WF_REOPEN;
        }

        for (size_t i = 0; i < GetWriteBlkNo(node->st.st_size); ++i) {
            if (node->wcache->taskid[i] == 0 &&
                (node->wcache->flags[i] & WF_DIRTY))              //如果这个block是脏的那么加个上传任务
            {
                block *b = (block *)malloc(sizeof(block));
                b->bno = i;
                b->node = node;
                node->wcache->taskid[i] = addtask((taskfunc) uploadblock, b, 0);
            }
        }
        node->unlockdate();
        node->unlockmeta();
        
        if (ret != len) {                   //返回真实写入长度
            return ret;
        }
        
        if ((size_t)len < size) {                   //需要写入下一个block
            int tmp = baiduapi_write(path, buf + len, size - len, offset + len, fi);
            if (tmp < 0) {                  //调用出错
                return tmp;
            } else {
                ret += tmp;
            }
        }
        return ret;
    }else{
        node->unlockmeta();
        errno = EPERM;
        return errno;
    }
}

//截断一个文件，只能截断读缓存中的文件，因为只有这种文件是可写的
int baiduapi_truncate(const char * path, off_t offset) {
    inode_t *node = getnode(path, false);

    if (node) {
        node->flag &= ~SYNCED;
        int ret = ftruncate(node->wcache->fd, offset);
        if(ret) {
            node->unlockmeta();
            return ret;
        }
        node->st.st_size = offset;
        node->unlockmeta();
        int oc = GetWriteBlkNo(node->st.st_size); //原来的块数
        int nc = GetWriteBlkNo(offset);   //扩展后的块数
        if (offset > node->st.st_size) {      //文件长度被扩展
            for(int i=oc; i<=nc; ++i){
                if (oc && (node->wcache->flags[oc] & WF_DIRTY) == 0) {
                    sem_wait(&wcache_sem);                                           //不能有太多的block没有同步
                }
                node->lockdate();
                node->wcache->flags[i] |= WF_DIRTY;
                if (node->wcache->flags[i] & WF_TRANS) {
                    node->wcache->flags[i] |= WF_REOPEN;
                }
                node->unlockdate();
            }
        }else{
            if (nc && (node->wcache->flags[nc] & WF_DIRTY) == 0) {
                sem_wait(&wcache_sem);                                           //不能有太多的block没有同步
            }
            node->lockdate();
            node->wcache->flags[nc] |= WF_DIRTY;
            if (node->wcache->flags[nc] & WF_TRANS) {
                node->wcache->flags[nc] |= WF_REOPEN;
            }
            for(int i=nc+1; i<=oc; ++i){
                node->wcache->flags[i] = 0;
            }
            node->unlockdate();
        }
        return 0;
    }
    return -EACCES;
}


int baiduapi_stub(const char *path)
{
    return 0;
}

