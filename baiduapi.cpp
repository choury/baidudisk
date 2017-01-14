#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <assert.h>
#include <fuse.h>
#include <signal.h>

#include <set>


#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include <json-c/json.h>


#include "utils.h"
#include "baiduapi.h"
#include "threadpool.h"
#include "cache.h"
#include "net.h"
#include "job.h"


static const char *basepath = "/apps/Native";
static const char *ak = "iN1yzFR9Sos27UWGEpjvKNVs";
static const char *sk = "wiz77wrFfUGje0oGGOaG3kOU7T18dSg2";


static char Access_Token[100];


/*处理百度服务器返回的各种乱七八糟的错误码，转换成errno形式的
 * 只有我经常碰到的错误，并且我能对应得上的一些
 * 如果返回111,即AT过期，则刷新AT
 */
static int handleerror(const char *msg)
{
//    errorlog("error mesage: %s\n", msg);
    json_object *json_get = json_tokener_parse(msg);
    if (json_get == NULL) {
        errorlog("json_tokener_parse filed!\n");
        return -EPROTO;
    }

    int error = 0;
    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        error = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
    }else{
        json_object_put(json_get);
        errorlog("get error code filed!\n");
        return -EPROTO;
    }
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

#define ERROR_CHECK(ret) \
    if(ret > CURL_LAST){ \
        ret = handleerror(bs.buf); \
        free(bs.buf); \
        return ret; \
    }\
    if(ret != CURLE_OK) { \
        errorlog("network error:%d\n", errno); \
        free(bs.buf); \
        return -EPROTO;\
    }


//顾名思义，将服务器传回的数据写到buff中
static size_t savetobuff(void *buffer, size_t size, size_t nmemb, void *user_p)
{
    buffstruct *bs = (buffstruct *) user_p;
    if(bs->buf == nullptr){
        assert(bs->offset == 0);
        assert(bs->len == 0);
        bs->buf = (char*)calloc(1024, 1);
        bs->len = 1024;
    }
    size_t len = size * nmemb;
    if(bs->offset + len > bs->len){
        bs->len = (bs->offset + len + 1023)/1024*1024;
        bs->buf = (char*)realloc(bs->buf, bs->len);
        memset(bs->buf + bs->offset, 0, bs->len - bs->offset);
    }
    memcpy(bs->buf + bs->offset, buffer, len);
    bs->offset += len;
    return len;
}

//你猜
static size_t readfrombuff(void *buffer, size_t size, size_t nmemb, void *user_p)
{
    buffstruct *bs = (buffstruct *) user_p;
    size_t len = std::min(size * nmemb, (bs->len) - bs->offset);
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
    char path[PATHLEN];
} block;


//从服务器读一个block
void readblock(block *tb) {
    block b = *tb;
    free(tb);
    size_t startp = b.bno * BLOCKLEN;
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, b.path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=download&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath).c_str());
    char *buf = nullptr;
    do{
        
        Http *r = Httpinit(buff);
        if (r == NULL) {
            errorlog("can't resolve domain:%s\n", strerror(errno));
            break;
        }
        
        r->method = Httprequest::get;
        
        buf = (char *)malloc(BLOCKLEN);
        buffstruct bs = {0, BLOCKLEN, buf};
        r->writefunc = savetobuff;
        r->writeprame = &bs;
        r->timeout = BLOCKLEN/(10*1024);
        
        char range[100] = {0};
        if((b.node->flag & CHUNKED) == 0){
            snprintf(range, sizeof(range) - 1, "%lu-%lu", startp, startp + BLOCKLEN - 1);
            r->range = range;
        }
        
        int ret = request(r);
        assert(bs.buf == buf);
        Httpdestroy(r);
        if (ret > CURL_LAST) {
            handleerror(bs.buf);
            break;
        }
        if(ret != CURLE_OK){
            errorlog("network error:%d\n", ret);
            break;
        }
        assert(bs.offset <= BLOCKLEN);
        assert(bs.buf == buf);
/*
        if(b.node->flag & CHUNKED)
            xorcode(bs.buf, startp, bs.offset, ak);
*/
        
        b.node->cache->lock();
        pwrite(b.node->cache->fd, bs.buf, bs.offset, startp);
        b.node->cache->chunks[b.bno].flag |= BL_SYNCED;
        b.node->cache->unlock();
    }while(0);
    free(buf);
    b.node->cache->lock();
    b.node->cache->taskid.erase(b.bno);
    b.node->cache->unlock();
}

//上传一个block作为chunkfile
void uploadblock(block *tb) {
    block b = *tb;
    free(tb);
    char buff[1024];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, b.path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "path=%s/%d&"
             "ondup=newcopy"
             , Access_Token, URLEncode(fullpath).c_str(), (int)b.bno%10);

    char *buf = nullptr;
    do{
        Http *r = Httpinit(buff);

        if (r == NULL) {
            errorlog("can't resolve domain:%s\n", strerror(errno));
            break;
        }

        buf = (char *)malloc(BLOCKLEN);
        buffstruct read_bs = {0, BLOCKLEN, buf};
        b.node->cache->lock();
        assert((b.node->cache->chunks[b.bno].flag & BL_TRANS) == 0);
        if((b.node->cache->chunks[b.bno].flag & BL_DIRTY) == 0){
            b.node->cache->unlock();
            break;
        }
        b.node->cache->chunks[b.bno].flag |= BL_TRANS;
        read_bs.len = pread(b.node->cache->fd, read_bs.buf, read_bs.len, b.bno*BLOCKLEN);
        b.node->cache->unlock();

/*
        if(b.node->flag & ENCRYPT)
            xorcode(read_bs.buf, GetWriteBlkStartPoint(b.bno), read_bs.len, ak);
*/
        
        r->method = Httprequest::post_formdata;
        r->readfunc = readfrombuff;
        r->readprame = &read_bs;
        r->length = read_bs.len;
        
        buffstruct write_bs ={0, 0, 0};
        r->writefunc = savetobuff;
        r->writeprame = &write_bs;
        r->timeout = BLOCKLEN/(10*1024);

        int ret = request(r);
        Httpdestroy(r);

        if(ret > CURL_LAST){
            handleerror(write_bs.buf);
            free(write_bs.buf);
            break;
        }
        if (ret != CURLE_OK) {
            errorlog("network error:%d\n", ret);
            free(write_bs.buf);
            break;
        }

        json_object * json_get = json_tokener_parse(write_bs.buf);
        free(write_bs.buf);

        if (json_get == NULL) {
            errorlog("json_tokener_parse filed!\n");
            break;
        }

        json_object *jpath;
        if (json_object_object_get_ex(json_get, "path",&jpath)) {
            b.node->cache->synced(b.bno, json_object_get_string(jpath)+strlen(fullpath)+1);
            json_object_put(json_get);
        } else {
            errorlog("Did not get path:%s\n", json_object_to_json_string(json_get));
        }
    }while(0);
    free(buf);
    b.node->cache->lock();
    b.node->cache->taskid.erase(b.bno);
    b.node->cache->chunks[b.bno].flag &= ~BL_REOPEN;
    b.node->cache->chunks[b.bno].flag &= ~BL_TRANS;
    b.node->cache->unlock();
}


/*获得Access_Token
 * 我曾经把自己模拟成浏览器手动post用户名密码，开始挺好使的
 * 后来不行了……因为登录次数多了居然要输验证码了！！！
 */
int gettoken() {
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

        Http *r = Httpinit(buff);

        if (r == NULL) {
            int lasterrno = errno;
            errorlog("can't resolve domain:%s\n", strerror(errno));
            return -lasterrno;
        }

        r->method = Httprequest::get;
        buffstruct bs = {0, 0, 0};
        r->writefunc = savetobuff;
        r->writeprame = &bs;

        int ret = request(r);
        Httpdestroy(r);
        ERROR_CHECK(ret);

        json_get = json_tokener_parse(bs.buf);
        free(bs.buf);

        if (json_get == NULL) {
            errorlog("json_tokener_parse filed!\n");
            return -EPROTO;
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

int refreshtoken() {
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
        r->method = Httprequest::get;
        buffstruct bs = {0, 0, 0};
        r->writefunc = savetobuff;
        r->writeprame = &bs;

        int ret = request(r);
        Httpdestroy(r);
        ERROR_CHECK(ret);

        json_get = json_tokener_parse(bs.buf);
        free(bs.buf);

        if (json_get == NULL) {
            errorlog("json_tokener_parse filed!\n");
            return -EPROTO;
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
void *baidu_init(struct fuse_conn_info *conn) {
    creatpool(THREADS);
    char basedir[PATHLEN];
    sprintf(basedir,"%s/.baidudisk",getenv("HOME"));
    mkdir(basedir,S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
    addtask((taskfunc)job_handle, nullptr, 0);
    conn->want = conn->capable & FUSE_CAP_BIG_WRITES;
    signal(SIGUSR1, (sighandler_t)cache_clear);
    return NULL;
}

void baidu_destroy(void *){
    cache_clear();
}

//获得文件属性……
int baidu_getattr(const char *path, struct stat *st) {
    bool chunked = endwith(path, ".def");

    inode_t* node = nullptr;
    char buff[2048];
    char fullpath[PATHLEN];
    memset(st, 0, sizeof(struct stat));
    st->st_nlink = 1;
    if(chunked){
        snprintf(fullpath, sizeof(fullpath) - 1, "%s%s/meta", basepath, path);
        snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=download&"
             "access_token=%s&"
             "path=%s",
             Access_Token, URLEncode(fullpath).c_str());
    }else{
        node = getnode(dirname(path).c_str(), false);
        const struct stat *st_get = node->getstat(basename(std::string(path)));
        if(st_get == nullptr && (node->flag & SYNCED)){
            node->unlock();
            return -ENOENT;
        }
        node->unlock();
        if(st_get){
            memcpy(st, st_get, sizeof(struct stat));
            return 0;
        }

        snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);
        snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=meta&"
             "access_token=%s&"
             "path=%s",
             Access_Token, URLEncode(fullpath).c_str());
    }

    Http *r = Httpinit(buff);
    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }
    r->method = Httprequest::get;
    buffstruct bs = {0, 0, 0};
    r->writefunc = savetobuff;
    r->writeprame = &bs;


    int ret = request(r);
    Httpdestroy(r);
    if(chunked){
        ERROR_CHECK(ret);

        node = getnode(decodepath(path).c_str(), true);
        memcpy(&node->st, bs.buf, sizeof(struct stat));
        memcpy(st, bs.buf, sizeof(struct stat));
        node->blocklist = (char (*)[20])(bs.buf+sizeof(struct stat));
        node->flag |= CHUNKED;
        node->unlock();
    }else{
        if (ret > CURL_LAST) {
            ret = handleerror(bs.buf);
            free(bs.buf);
            if(ret == -ENOENT){
                return baidu_getattr(encodepath(path).c_str(), st);
            }
            return ret;
        }

        if (ret != CURLE_OK) {
            errorlog("network error:%d\n", ret);
            free(bs.buf);
            return -EPROTO;
        }
        json_object *json_get = json_tokener_parse(bs.buf);
        free(bs.buf);

        if (json_get == NULL) {
            errorlog("json_tokener_parse filed!\n");
            return -EPROTO;
        }

        json_object *jlist;
        json_object_object_get_ex(json_get, "list",&jlist);
        json_object *filenode = json_object_array_get_idx(jlist, 0);

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
        node->add_cache(basename(std::string(path)), *st);
    }
    return 0;
}

int baidu_fgetattr(const char* path, struct stat* st, struct fuse_file_info* fi){
    inode_t *node = (inode_t*)fi->fh;
    node->lock();
    memcpy(st, &node->st, sizeof(struct stat));
    node->unlock();
    return 0;
}

//读取目录下面有什么文件
int baidu_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    inode_t* node = getnode(path, true);
    assert(node->cache == nullptr);
    if(node->filldir(buf, filler)){
        node->unlock();
        return 0;
    }
    node->unlock();

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
             , Access_Token, URLEncode(fullpath).c_str());

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    r->method = Httprequest::get;
    buffstruct bs = {0, 0, 0};
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    Httpdestroy(r);
    ERROR_CHECK(ret);

    json_object *json_get = json_tokener_parse(bs.buf);
    free(bs.buf);

    if (json_get == NULL) {
        errorlog("json_tokener_parse filed!\n");
        return -EPROTO;
    }

    json_object *jlist;
    json_object_object_get_ex(json_get, "list",&jlist);
    
    node->lock();
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
        node->add_cache(childname, st);
    }
    node->flag |= SYNCED;
    node->filldir(buf, filler);
    node->unlock();

    json_object_put(json_get);
    return 0;
}


//获得文件系统信息，对于百度网盘来说，只有容量是有用的……
int baidu_statfs(const char *path, struct statvfs *sf)
{
    char buff[1025];
    sprintf(buff,
            "https://pcs.baidu.com/rest/2.0/pcs/quota?"
            "method=info&"
            "access_token=%s", Access_Token);

    Http *r = Httpinit(buff);
    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    r->method = Httprequest::get;
    buffstruct bs = {0, 0, 0};
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    Httpdestroy(r);
    ERROR_CHECK(ret);

    json_object *json_get = json_tokener_parse(bs.buf);
    free(bs.buf);

    if (json_get == NULL) {
        errorlog("json_tokener_parse filed!\n");
        return -EPROTO;
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
int baidu_mkdir(const char *path, mode_t mode) {
    (void) mode;
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=mkdir&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath).c_str());


    Http *r = Httpinit(buff);
    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    r->method = Httprequest::get;
    buffstruct bs = {0, 0, 0};
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    Httpdestroy(r);
    ERROR_CHECK(ret);

    json_object *json_get = json_tokener_parse(bs.buf);
    free(bs.buf);

    if (json_get == NULL) {
        errorlog("json_tokener_parse filed!\n");
        return -EPROTO;
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
    node->unlock();
    return 0;
}


//删除文件（文件夹需使用rmdir）
int baidu_unlink(const char *path) {
    inode_t* node = getnode(path, false);
    if(node == nullptr){
        return -ENOENT;
    }
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, node->getcwd().c_str());
    node->unlock();
    
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=delete&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath).c_str());

    Http *r = Httpinit(buff);
    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    r->method = Httprequest::get;
    buffstruct bs = {0, 0, 0};
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    Httpdestroy(r);
    ERROR_CHECK(ret);

    free(bs.buf);
    node->remove();
    return 0;
}

//删除文件夹
int baidu_rmdir(const char *path) {
    inode_t* node = getnode(path, false);
    if(node){
        if(node->flag & SYNCED){
            assert(node->cache == nullptr);
            if(!node->empty()){
                node->unlock();
                return -ENOTEMPTY;
            }
        }
        node->unlock();
    }else{
        char buff[2048];
        char fullpath[PATHLEN];
        snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);

        snprintf(buff, sizeof(buff) - 1,
                 "https://pcs.baidu.com/rest/2.0/pcs/file?"
                 "method=list&"
                 "access_token=%s&"
                 "path=%s&limit=0-1"
                 , Access_Token, URLEncode(fullpath).c_str());

        Http *r = Httpinit(buff);
        if (r == NULL) {
            int lasterrno = errno;
            errorlog("can't resolve domain:%s\n", strerror(errno));
            return -lasterrno;
        }

        r->method = Httprequest::get;
        buffstruct bs = {0, 0, 0};
        r->writefunc = savetobuff;
        r->writeprame = &bs;

        int ret = request(r);
        Httpdestroy(r);
        ERROR_CHECK(ret);

        json_object *json_get = json_tokener_parse(bs.buf);
        free(bs.buf);

        if (json_get == NULL) {
            errorlog("json_tokener_parse filed!\n");
            return -EPROTO;
        }

        json_object *jlist;
        json_object_object_get_ex(json_get, "list",&jlist);
        if (json_object_array_length(jlist) != 0) {
            json_object_put(json_get);
            return -ENOTEMPTY;
        }
        json_object_put(json_get);
    }

    return baidu_unlink(path);
}


/* 想猜你就继续猜吧
 */
int baidu_rename(const char *oldname, const char *newname) {
    inode_t *node = getnode(oldname, false);
    if(node == nullptr){
        return -ENOENT;
    }
    char buff[3096];
    char oldfullpath[PATHLEN];
    char newfullpath[PATHLEN];
    snprintf(oldfullpath, sizeof(oldfullpath) - 1, "%s%s", basepath, node->getcwd().c_str());
    if(node->flag & CHUNKED){
        snprintf(newfullpath, sizeof(newfullpath) - 1, "%s%s", basepath, encodepath(newname).c_str());
    }else{
        snprintf(newfullpath, sizeof(newfullpath) - 1, "%s%s", basepath, newname);
    }
    node->unlock();

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=move&"
             "access_token=%s&"
             "from=%s&"
             "to=%s"
             , Access_Token, URLEncode(oldfullpath).c_str(), URLEncode(newfullpath).c_str());
    
    Http *r = Httpinit(buff);
    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    r->method = Httprequest::get;
    buffstruct bs = {0, 0, 0};
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    Httpdestroy(r);
    ERROR_CHECK(ret);

    free(bs.buf);
    node->move(newname);
    return 0;
}

//创建一个文件，并把它加到filelist里面
int baidu_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) mode;
    inode_t *node = getnode(path, true);
    assert(node->cache == nullptr);
    assert(node->opened == 0);
    
    node->cache = new fcache();
    node->opened = 1;
    node->flag |= CHUNKED;
    
    node->st.st_ino  = 1;
    node->st.st_nlink = 1;
    node->st.st_size = 0;
    node->st.st_mode = S_IFREG | 0666;
    node->st.st_ctime = time(NULL);
    node->st.st_mtime = time(NULL);

    fi->fh = (uint64_t) node;
    node->unlock();
    return 0;
}


/*
 * 打开一个文件，如果这个文件在缓存里面存在，直接指向它，并将计数器加一
 * 如果只读打开的话，生成一个读缓存文件
 * 如果只写，读写打开，这个文件在服务器上存在的话，不行！
 * 否则，返回文件不存在
 */
int baidu_open(const char *path, struct fuse_file_info *fi) {
    inode_t* node = getnode(path, false);
    if((node->flag & CHUNKED) == 0 &&
       (fi->flags & O_ACCMODE) != O_RDONLY)
    {
        node->unlock();
        return -EACCES;
    }
    if(node->cache){
        node->opened++;
        fi->fh = (uint64_t)node;
        node->unlock();
        return 0;
    }
    assert(node->opened == 0);

    node->cache = new fcache();
    assert(((node->flag & CHUNKED) && node->blocklist) ||
           ((node->flag & CHUNKED) == 0 && node->blocklist == nullptr));
    if(node->blocklist){
        if(node->st.st_size){
            for(size_t i=0;i <= GetBlkNo(node->st.st_size);i++){
                strcpy(node->cache->chunks[i].name, node->blocklist[i]);
            }
        }
    }
    node->opened = 1;
    fi->fh = (uint64_t) node;
    node->unlock();
    return 0;
}

/*
 * 释放一个文件
 */
int baidu_release(const char *path, struct fuse_file_info *fi)
{
    inode_t *node = (inode_t*) fi->fh;
    node->release();
    return 0;
}


//读
int baidu_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    inode_t *node = (inode_t *) fi->fh;
    node->lock();
    assert(node->cache);
    if (offset > node->st.st_size) {        //如果偏移超过文件长度
        node->unlock();
        errno = EFAULT;
        return -errno;
    }

    if (offset + size > (size_t)node->st.st_size) {   //如果剩余长度不足size，则最多读到文件末尾
        size = node->st.st_size - offset;
    }
    int c = offset / BLOCKLEN;  //计算一下在哪个块
    size_t p = c;
    node->cache->lock();
    do{             //一般读取的时候绝大部分是向后读，所以缓存下面的几个block
        if(p > GetBlkNo(node->st.st_size)){
            break;
        }
        if (node->cache->taskid.count(p) == 0 &&
            (node->cache->chunks[p].flag & BL_SYNCED) == 0)
        {
            block *b = (block *) malloc(sizeof(block));
            b->node = node;
            b->bno = p;
            if(node->flag & CHUNKED){
                sprintf(b->path, "%s/%s", node->getcwd().c_str(), node->cache->chunks[p].name);
            }else{
                strcpy(b->path, node->getcwd().c_str());
            }
            node->cache->taskid[p] = addtask((taskfunc) readblock, b, 0);
            node->flag &= ~SYNCED;
        }
        p++;
    }while (node->cache->taskid.size() < CACHEC);
    node->unlock();
    if(node->cache->taskid.count(c)){
        task_t taskid = node->cache->taskid[c];
        node->cache->unlock();
        waittask(taskid);
        node->cache->lock();
    }
    if ((node->cache->chunks[c].flag & BL_SYNCED) ==0 ) {
        node->cache->unlock();
        return baidu_read(path, buf, size, offset, fi);  //如果在这里返回那么读取出错,重试
    }
    size_t len = std::min(size, GetBlkEndPointFromP(offset) - offset);      //计算最长能读取的字节
    ssize_t ret = pread(node->cache->fd, buf, len, offset);
    node->cache->unlock();
    if (ret != (ssize_t)len) {                   //读取出错了
        return ret;
    }

    if (len < size) {                   //需要读取下一个block
        int tmp = baidu_read(path, buf + len, size - len, offset + len, fi);
        if (tmp < 0) {                  //调用出错
            return tmp;
        } else
            ret += tmp;
    }

    return ret;                         //成功返回
}

#if 0
//上传一个文件
int baidu_uploadfile(const char *path, inode_t* node) {
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath)-1, "%s%s", basepath, path);
    snprintf(buff, sizeof(buff) - 1,
             "https://c.pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "path=%s&"
             "ondup=overwrite"
             , Access_Token, URLEncode(fullpath).c_str());

    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    assert(node->type == cache_type::write);
    int file = node->wcache->fd;
    r->method = Httprequest::post_formdata;
    if(node->flag & CHUNKED){
        r->readfunc = readfromfdxor;
    }else{
        r->readfunc = readfromfd;
    }
    r->readprame = (void *)(long)file;
    r->length = lseek(file, 0, SEEK_END);
    lseek(file, 0, SEEK_SET);

    buffstruct bs = {0, 0, 0};
    r->writefunc = savetobuff;
    r->writeprame = &bs;
    r->closefunc = freebuff;
    r->closeprame = &bs;
    r->timeout = r->length/(10*1024) + 10;
    if ((errno = request(r)) != CURLE_OK) {
        errorlog("network error:%d\n", errno);
        Httpdestroy(r);
        return -EPROTO;
    }

    json_object *json_get= json_tokener_parse(bs.buf);
    Httpdestroy(r);

    if (json_get == NULL) {
        errorlog("json_tokener_parse filed!\n");
        return -EPROTO;
    }

    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        int errorno = json_object_get_int(jerror_code) ;
        errorlog("get error:%s\n", json_object_to_json_string(json_get));
        json_object_put(json_get);
        return handleerror(errorno);
    }else{
        json_object *jmtime;
        json_object_object_get_ex(json_get, "mtime",&jmtime);
        node->st.st_mtime = json_object_get_int64(jmtime);

        json_object *jctime;
        json_object_object_get_ex(json_get, "ctime",&jctime);
        node->st.st_ctime = json_object_get_int64(jctime);

        json_object *jfs_id;
        json_object_object_get_ex(json_get, "fs_id",&jfs_id);
        node->st.st_ino = json_object_get_int64(jfs_id);

        json_object *jsize;
        json_object_object_get_ex(json_get, "size",&jsize);
        node->st.st_size = json_object_get_int64(jsize);
        json_object_put(json_get);
        return 0;
    }
}
#endif


//把上传的临时文件合并成一个文件
int baidu_uploadmeta(inode_t *node) {
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s/meta", basepath, node->getcwd().c_str());
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "path=%s&"
             "ondup=overwrite"
             , Access_Token, URLEncode(fullpath).c_str());

    size_t len = sizeof(struct stat) + (GetBlkNo(node->st.st_size)+1)*20;
    char *param = (char *)malloc(len);
    memcpy(param, &node->st, sizeof(struct stat));
    if(node->blocklist){
        free((char *)(node->blocklist)-sizeof(struct stat));
    }
    node->blocklist = (char (*)[20])(param+sizeof(struct stat));
    for (size_t i = 0; i <= GetBlkNo(node->st.st_size); ++i) {
        memcpy(node->blocklist[i], node->cache->chunks[i].name, 20);
    }

    buffstruct read_bs = {0, len, param};
    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    r->method = Httprequest::post_formdata;
    r->readfunc = readfrombuff;
    r->readprame = &read_bs;
    r->length = read_bs.len;
    
    buffstruct bs = {0, 0, 0};
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    Httpdestroy(r);
    ERROR_CHECK(ret);

    free(bs.buf);
    return 0;
}


/*
 * 同步一个文件，如果flag被置位的话就等直到这些文件真的被同步成功
 * 否则只是添加一个任务，然后结果什么样就不管了
 * 说实话，我并不知道这个flag原来实际上是什么用……
 */
int filesync(inode_t *node, int sync_meta){
    node->lock();
    if(node->flag & SYNCED){
        node->unlock();
        return 0;
    }
    if(node->cache == nullptr){
        node->flag |= SYNCED;
    }else if(node->flag & CHUNKED){
        node->cache->lock();
        int dirty;
        do {
            dirty = 0;
            std::set<task_t> waitset;
            for (size_t i = 0; i <= GetBlkNo(node->st.st_size); ++i) {
                if (node->cache->taskid.count(i)) {
                    waitset.insert(node->cache->taskid[i]);
                }else if (node->st.st_nlink && (node->cache->chunks[i].flag & BL_DIRTY)) {
                    block *b = (block *)malloc(sizeof(block));
                    b->bno = i;
                    b->node =  node;
                    strcpy(b->path, node->getcwd().c_str());
                    task_t taskid = addtask((taskfunc) uploadblock, b, 0);
                    node->cache->taskid[i] = taskid;
                    waitset.insert(taskid);
                    dirty = 1;
                }
            }
            node->cache->unlock();
            for(auto i:waitset){
                waittask(i);
            }
            node->cache->lock();
        }while(dirty);
        if(sync_meta){
            while (baidu_uploadmeta(node));
            node->flag |= SYNCED;
        }
        node->cache->unlock();
    }else{
        node->cache->lock();
        while(node->cache->taskid.size()){
            task_t taskid = node->cache->taskid.begin()->second;
            node->cache->unlock();
            waittask(taskid);
            node->cache->lock();
        }
        node->cache->unlock();
        node->flag |= SYNCED;
    }
    node->unlock();
    return 0;
}

int baidu_fsync(const char *, int flag, struct fuse_file_info *fi) {
    inode_t *node = (inode_t *) fi->fh;
    return filesync(node, flag);
}


int baidu_flush(const char * path, struct fuse_file_info *fi){
    return baidu_fsync(path, 1, fi);
}
/*
 * 写文件，只有本地的文件才可以写，已经传到服务器上的就不能写了
 *
 */
int baidu_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    inode_t* node = (inode_t *) fi->fh;
    int c = offset / BLOCKLEN;   //计算一下在哪个块
    int len = std::min(size, GetBlkEndPointFromP(offset) - offset);      //计算最长能写入的字节
    node->lock();
    if(node->cache == nullptr || (node->flag & CHUNKED) == 0){
        node->unlock();
        errno = EPERM;
        return errno;
    }
    if(offset > node->st.st_size) {
        baidu_ftruncate(path, offset, fi);
    }
    node->cache->lock();
    task_t taskid = 0;
    node->unlock();
    if (node->cache->chunks.count(c)){
        if(node->cache->taskid.count(c) == 0 &&
           (node->cache->chunks[c].flag & BL_SYNCED) == 0)
        {
            block *b = (block *) malloc(sizeof(block));
            b->node = node;
            b->bno = c;
            sprintf(b->path, "%s/%s", node->getcwd().c_str(), node->cache->chunks[c].name);
            node->cache->taskid[c] = addtask((taskfunc) readblock, b, 0);
        }
        if(node->cache->taskid.count(c)){
            taskid = node->cache->taskid[c];
        }
        node->cache->unlock();
        waittask(taskid);
        node->cache->lock();
        if((node->cache->chunks[c].flag & BL_SYNCED) == 0){
            node->cache->unlock();
            return -EAGAIN;
        }
    }
    node->cache->unlock();
    int ret = node->cache->write(buf, len, offset);
    node->lock();
    if(ret>0 && ret + offset > node->st.st_size){
        node->st.st_size = ret + offset;
    }
    node->flag &= ~SYNCED;
    node->cache->lock();
    for (size_t i = 0; i < GetBlkNo(node->st.st_size); ++i) {
        if (node->cache->taskid.count(i) == 0 &&
            (node->cache->chunks[i].flag & BL_DIRTY))              //如果这个block是脏的那么加个上传任务
        {
            block *b = (block *)malloc(sizeof(block));
            b->bno = i;
            b->node = node;
            strcpy(b->path, node->getcwd().c_str());
            node->cache->taskid[i] = addtask((taskfunc) uploadblock, b, 0);
        }
    }
    node->cache->unlock();
    node->st.st_mtime= time(NULL);
    node->unlock();
    if(ret != (ssize_t)len) {                   //读取出错了
        return ret;
    }
    if((size_t)len < size) {                   //需要读取下一个block
        int tmp = baidu_write(path, buf + len, size - len, offset + len, fi);
        if (tmp < 0) {                  //调用出错
            return tmp;
        } else
            ret += tmp;
    }
    return ret;
}

//截断一个文件，只能截断读缓存中的文件，因为只有这种文件是可写的
int baidu_ftruncate(const char* path, off_t offset, struct fuse_file_info *fi){
    inode_t* node = (inode_t *) fi->fh;
    node->lock();
    int ret = node->cache->truncate(node->st.st_size, offset);
    if(ret == 0){
        node->flag &= ~SYNCED;
        node->st.st_size = offset;
        node->cache->lock();
        for (size_t i = 0; i < GetBlkNo(node->st.st_size); ++i) {
            if (node->cache->taskid.count(i) == 0 &&
                (node->cache->chunks[i].flag & BL_DIRTY))              //如果这个block是脏的那么加个上传任务
            {
                block *b = (block *)malloc(sizeof(block));
                b->bno = i;
                b->node = node;
                strcpy(b->path, node->getcwd().c_str());
                node->cache->taskid[i] = addtask((taskfunc) uploadblock, b, 0);
            }
        }
        node->cache->unlock();
        node->st.st_mtime= time(NULL);
    }
    node->unlock();
    return ret;
}

int baidu_truncate(const char* path, off_t offset) {
    inode_t *node = getnode(path, false);
    if (node) {
        node->unlock();
        struct fuse_file_info fi;
        fi.fh = (uint64_t)node;
        return baidu_ftruncate(path, offset, &fi);
    }
    return -EACCES;
}

//only user.encrypt supported
int baidu_getxattr(const char *path, const char *name, char *value, size_t len){
    if(strcmp(name, "user.chunked")){
        return -ENODATA;
    }
    if(len == 0){
        return sizeof(char);
    }
    if(len < sizeof(char)){
        return -ERANGE;
    }
    inode_t *node = getnode(path, false);
    if(node->flag & CHUNKED){
        value[0]='1';
    }else{
        value[0]='0';
    }
    node->unlock();
    return sizeof(char);
}


int baidu_stub(const char *path)
{
    return 0;
}

