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
    errorlog("msg: %s", msg);
    if(msg == nullptr){
        errno = EIO;
        return -errno;
    }
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
        errno = EINVAL;
        break;

    case 31064:
        errno = EACCES;
        break;

    case 31066:
        errno = ENOENT;
        break;
        
    case 31074:
        errno = EISDIR;
        break;
        
    case 31202:
        errno = ENOENT;
        break;

    case 31212:
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
        errorlog("network error:%d\n", ret); \
        free(bs.buf); \
        return -EPROTO;\
    }



void job_handle(){
    while(true){
        uint32_t t = do_job();
        sleep(t>30?30:t);
    }
}

typedef struct {
    fcache *file;
    size_t  bno;
    blksize_t blksize;
    char path[PATHLEN];
} block_param;

//从服务器读一个block
void readblock(block_param *bp) {
    block_param param = *bp;
    free(bp);
    size_t startp = param.bno * param.blksize;
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, param.path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=download&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath).c_str());
    int ret = 0;
    buffstruct bs = {0, (size_t)param.blksize + 1, (char *)calloc(param.blksize + 1, 1)};
    do{
        Http *r = Httpinit(buff);
        if (r == NULL) {
            ret = errno;
            errorlog("can't resolve domain:%s\n", strerror(errno));
            break;
        }
        
        r->method = Httprequest::get;
        r->writefunc = savetobuff;
        r->writeprame = &bs;
        r->timeout = param.blksize/(5*1024); //不得小于5K/s
        
        char range[100] = {0};
        if((param.file->flag & CHUNKED) == 0){
            snprintf(range, sizeof(range) - 1, "%zu-%lu", startp, startp + param.blksize - 1);
            r->range = range;
        }
        
        ret = request(r);
        Httpdestroy(r);
        if (ret > CURL_LAST) {
            handleerror(bs.buf);
            break;
        }
        if(ret != CURLE_OK){
            errorlog("network error:%d\n", ret);
            break;
        }
        assert(bs.offset <= (size_t)param.blksize);
    }while(0);
    param.file->lock();
    if(ret == 0 && (param.file->chunks[param.bno]->flag & BL_SYNCED) == 0){
        if(param.file->flag & ENCRYPT)
            xorcode(bs.buf, startp, bs.offset, ak);
        pwrite(param.file->fd, bs.buf, bs.offset, startp);
        param.file->chunks[param.bno]->flag |= BL_SYNCED;
    }
    param.file->taskid.erase(param.bno);
    param.file->unlock();
    free(bs.buf);
}

//上传一个block作为chunkfile
void uploadblock(block_param *bp) {
    block_param param = *bp;
    free(bp);
    char buff[1024];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, param.path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "path=%s/%zu&"
             "ondup=newcopy"
             , Access_Token, URLEncode(fullpath).c_str(), param.bno);
    int ret = 0;
    buffstruct read_bs = {0, (size_t)param.blksize, (char *)malloc(param.blksize)};
    do{
        Http *r = Httpinit(buff);
        if (r == NULL) {
            ret = errno;
            errorlog("can't resolve domain:%s\n", strerror(errno));
            break;
        }

        param.file->lock();
        if((param.file->chunks.count(param.bno)) == 0){ //it was truncated
            param.file->unlock();
            ret = ENOENT;
            break;
        }
        assert(param.file->chunks[param.bno]->flag & BL_DIRTY);
        assert((param.file->chunks[param.bno]->flag & BL_TRANS) == 0);
        param.file->chunks[param.bno]->flag |= BL_TRANS;
        read_bs.len = pread(param.file->fd, read_bs.buf, read_bs.len, param.bno*param.blksize);
        if(param.file->flag & ENCRYPT)
            xorcode(read_bs.buf, param.bno * param.blksize, read_bs.len, ak);
        param.file->unlock();

        r->method = Httprequest::post_formdata;
        r->readfunc = readfrombuff;
        r->readprame = &read_bs;
        r->length = read_bs.len;
        
        buffstruct write_bs ={0, 0, 0};
        r->writefunc = savetobuff;
        r->writeprame = &write_bs;
        r->timeout = param.blksize/(2*1024); //不得小于2K/s

        ret = request(r);
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
            ret = EPROTO;
            break;
        }

        json_object *jpath;
        if (json_object_object_get_ex(json_get, "path",&jpath)) {
            param.file->synced(param.bno, json_object_get_string(jpath)+strlen(fullpath)+1);
            json_object_put(json_get);
        } else {
            errorlog("Did not get path:%s\n", json_object_to_json_string(json_get));
        }
    }while(0);
    param.file->lock();
    param.file->chunks[param.bno]->flag &= ~BL_REOPEN;
    param.file->chunks[param.bno]->flag &= ~BL_TRANS;
    param.file->taskid.erase(param.bno);
    param.file->unlock();
    free(read_bs.buf);
}

int readchunkattr(entry_t *entry) {
    entry->lock();
    assert(entry->flag & CHUNKED);
    assert(endwith(entry->path, ".def") == 0);
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s/meta.json", basepath, entry->getcwd().c_str());
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=download&"
             "access_token=%s&"
             "path=%s",
             Access_Token, URLEncode(fullpath).c_str());

    int ret = 0;
    buffstruct bs = {0, 0, 0};
    do{
        Http *r = Httpinit(buff);
        if (r == NULL) {
            ret = errno;
            errorlog("can't resolve domain:%s\n", strerror(errno));
            break;
        }
        r->method = Httprequest::get;
        r->writefunc = savetobuff;
        r->writeprame = &bs;
        
        ret = request(r);
        Httpdestroy(r);
        if(ret > CURL_LAST){
            ret = handleerror(bs.buf);
            break;
        }
        if (ret != CURLE_OK) {
            errorlog("network error:%d\n", ret);
            ret = -EPROTO;
            break;
        }
        
        json_object *json_get = json_tokener_parse(bs.buf);
        if (json_get == NULL) {
            errorlog("json_tokener_parse filed!\n");
            ret = -EPROTO;
            break;
        }
        
        struct stat st;
        memset(&st, 0, sizeof(struct stat));
        st.st_nlink = 1;
        json_object *jmtime;
        json_object_object_get_ex(json_get, "mtime",&jmtime);
        st.st_mtime = json_object_get_int64(jmtime);
        
        json_object *jctime;
        json_object_object_get_ex(json_get, "ctime",&jctime);
        st.st_ctime = json_object_get_int64(jctime);
        
        json_object *jsize;
        json_object_object_get_ex(json_get, "size",&jsize);
        st.st_size = json_object_get_int64(jsize);
        
        json_object *jblksize;
        json_object_object_get_ex(json_get, "blksize",&jblksize);
        st.st_blksize = json_object_get_int64(jblksize);
        assert(st.st_blksize % 4096 == 0);

        st.st_mode = S_IFREG | 0666;
        entry->add_entry("", &st);

        json_object *jblock_list;
        json_object_object_get_ex(json_get, "block_list",&jblock_list);

        entry->blocklist = json_object_get(jblock_list);
        json_object *jencoding;
        json_object_object_get_ex(json_get, "encoding", &jencoding);
        const char *encoding = json_object_get_string(jencoding);
        if(strcasecmp(encoding, "xor") == 0){
            entry->flag |= ENCRYPT;
        }else{
            assert(strcasecmp(encoding, "none") == 0);
        }
        entry->flag |= CHUNKED;
        json_object_put(json_get);
    }while(0);
    entry->unlock();
    free(bs.buf);
    return ret;
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
    cache_init();
    signal(SIGUSR1, (sighandler_t)cache_destory);
    return NULL;
}

void baidu_destroy(void *){
    cache_destory();
}


int baidu_fgetattr(const char* path, struct stat* st, struct fuse_file_info* fi){
    entry_t *entry = (entry_t*)fi->fh;
    entry->lock();
    assert(entry->flag & META_PULLED);
    memcpy(st, &entry->st, sizeof(struct stat));
    entry->unlock();
    return 0;
}

int baidu_opendir_e(entry_t* entry){
    entry->opened ++;
    if(entry->flag & GETCHILDREN){
        return 0;
    }
    assert(entry->dir);
    char buff[2048];
    char fullpath[PATHLEN];
    sprintf(fullpath, "%s%s/", basepath, entry->getcwd().c_str());

    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    st.st_nlink = 1;

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=list&"
             "limit=0-10000&"
             "by=time&"
             "order=desc&"
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

    entry->dir->lock();
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
        st.st_blksize = BLOCKLEN;

        json_object *jisdir;
        json_object_object_get_ex(filenode, "isdir",&jisdir);
        if (json_object_get_boolean(jisdir)) {
            st.st_mode = S_IFDIR | 0755;
        } else {
            st.st_mode = S_IFREG | 0444;
        }

        json_object *jpath;
        json_object_object_get_ex(filenode, "path", &jpath);
        const char *bpath = json_object_get_string(jpath) + strlen(basepath);
        if(endwith(bpath, ".def")){
            std::string realpath = decodepath(bpath);
            std::string bname = basename(realpath);
            entry_t* e = getentryAt(entry, bname);
            if(e){
                assert(e->flag & CHUNKED);
                e->unlock();
                continue;
            }
            e = entry->add_entry(bname, (struct stat*)nullptr);
            e->flag |= CHUNKED;
            entry->dir->taskid[bname] = addtask((taskfunc)readchunkattr, e, 0);
        }else{
            entry->add_entry(basename(bpath), &st);
        }
    }
    json_object_put(json_get);
    entry->dir->unlock();
    entry->flag |= GETCHILDREN;
    return 0;
}

int baidu_opendir(const char *path, struct fuse_file_info *fi){
    entry_t* entry = getentry(path);
    assert(entry->file == nullptr);
    fi->fh = (uint64_t)entry;
    int ret = baidu_opendir_e(entry);
    entry->unlock();
    return ret;
}

//读取目录下面有什么文件
int baidu_readdir(const char* path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    entry_t* entry = (entry_t *)fi->fh;
    entry->lock();
    assert(entry->getcwd() == path);
    assert(entry->file == nullptr);
    entry->dir->lock();
    for(auto i:entry->dir->entrys){
        if((i->flag & META_PULLED) || entry->dir->taskid.count(i->path)){
            continue;
        }
        entry->dir->taskid[i->path] = addtask((taskfunc)readchunkattr, i, 0);
    }
    entry->filldir(buf, filler);
    entry->dir->unlock();
    entry->unlock();
    return 0;
}

int baidu_relasedir_e(entry_t *entry){
    assert(entry->file == nullptr);
    entry->dir->lock();
    entry->unlock();
    while(!entry->dir->taskid.empty()){
        auto i = entry->dir->taskid.begin();
        std::string path = i->first;
        task_t taskid = i->second;
        entry->dir->unlock();
        waittask(taskid);
        entry->dir->lock();
        entry->dir->taskid.erase(path);
    }
    entry->dir->unlock();
    entry->lock();
    entry->opened --;
    return 0;
}

int baidu_releasedir(const char* path, struct fuse_file_info *fi){
    entry_t* entry = (entry_t *)fi->fh;
    entry->lock();
    assert(entry->getcwd() == path);
    int ret = baidu_relasedir_e(entry);
    entry->unlock();
    return ret;
}

//获得文件属性……
int baidu_getattr(const char *path, struct stat *st) {
    if(strcmp(path, "/") == 0){
        st->st_nlink = 1;
        st->st_mode = S_IFDIR | 0755;
        return 0;
    }
    std::string dname = dirname(path);
    std::string bname = basename(path);
    entry_t* pentry = getentry(dname.c_str());
    if(pentry == nullptr){
        return -ENOENT;
    }
    entry_t* entry = getentryAt(pentry, bname);
    if(entry == nullptr){
        if(pentry->flag & GETCHILDREN){
            pentry->unlock();
            return -ENOENT;
        }
        baidu_opendir_e(pentry);
        baidu_relasedir_e(pentry);
        entry = getentryAt(pentry, bname);
        if(entry == nullptr){
            pentry->unlock();
            return -ENOENT;
        }
    }
    pentry->dir->lock();
    entry->unlock();
    if(pentry->dir->taskid.count(bname)){
        task_t taskid = pentry->dir->taskid[bname];
        pentry->dir->unlock();
        waittask(taskid);
        pentry->dir->lock();
        pentry->dir->taskid.erase(bname);
    }
    entry->lock();
    pentry->dir->unlock();
    pentry->unlock();
    if(entry->flag & META_PULLED){
        memcpy(st, &entry->st, sizeof(struct stat));
        entry->unlock();
        return 0;
    }

    int ret = readchunkattr(entry);
    if( ret == 0){
        assert(entry->flag & META_PULLED);
        memcpy(st, &entry->st, sizeof(struct stat));
    }
    entry->unlock();
    return ret;
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

    struct stat st;
    memset(&st, 0, sizeof(st));
    st.st_nlink = 1;
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
    
    entry_t *entry = getentry(dirname(path).c_str());
    entry->add_entry(basename(path), &st)->flag = META_PULLED | META_PUSHED | GETCHILDREN;
    entry->unlock();
    return 0;
}


//删除文件（文件夹需使用rmdir）
int baidu_unlink(const char *path) {
    entry_t* entry = getentry(path);
    if(entry == nullptr){
        return -ENOENT;
    }
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, entry->getcwd().c_str());
    entry->unlock();
    
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
    if(ret > CURL_LAST){
        ret = handleerror(bs.buf);
        free(bs.buf);
        if(ret == -ENOENT){
            entry->remove();
            return 0;
        }
        return ret;
    }
    if(ret != CURLE_OK) {
        errorlog("network error:%d\n", ret);
        free(bs.buf);
        return -EPROTO;
    }

    free(bs.buf);
    entry->remove();
    return 0;
}

//删除文件夹
int baidu_rmdir(const char *path) {
    entry_t* entry = getentry(path);
    if(entry){
        assert(entry->file == nullptr);
        if(!entry->empty()){
            entry->unlock();
            return -ENOTEMPTY;
        }else if(entry->flag & GETCHILDREN){
            entry->unlock();
            return baidu_unlink(path);
        }
        entry->unlock();
    }
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
    return baidu_unlink(path);
}


/* 想猜你就继续猜吧
 */
int baidu_rename(const char *oldname, const char *newname) {
    entry_t *oldentry = getentry(oldname);
    if(oldentry == nullptr){
        return -ENOENT;
    }
    char buff[3096];
    char oldfullpath[PATHLEN];
    char newfullpath[PATHLEN];
    snprintf(oldfullpath, sizeof(oldfullpath) - 1, "%s%s", basepath, oldentry->getcwd().c_str());
    if(oldentry->flag & CHUNKED){
        snprintf(newfullpath, sizeof(newfullpath) - 1, "%s%s", basepath, encodepath(newname).c_str());
    }else{
        snprintf(newfullpath, sizeof(newfullpath) - 1, "%s%s", basepath, newname);
    }
    oldentry->unlock();
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
    if(ret > CURL_LAST){
        ret = handleerror(bs.buf);
        free(bs.buf);
        if(ret == -EEXIST){
            snprintf(buff, sizeof(buff) - 1,
                 "https://pcs.baidu.com/rest/2.0/pcs/file?"
                 "method=delete&"
                 "access_token=%s&"
                 "path=%s"
                 , Access_Token,  URLEncode(newfullpath).c_str());

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
            request(r);
            free(bs.buf);
            return baidu_rename(oldname, newname);
        }
        return ret;
    }
    if(ret != CURLE_OK) {
        errorlog("network error:%d\n", ret);
        free(bs.buf);
        return -EPROTO;
    }
    free(bs.buf);
    entry_t *newentry = getentry(newname);
    if(newentry){
        newentry->unlock();
        newentry->remove();
    }
    oldentry->move(newname);
    return 0;
}

//创建一个文件，并把它加到filelist里面
int baidu_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    (void) mode;
    entry_t *entry = getentry(dirname(path).c_str());
    assert(entry->file == nullptr);
    
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    st.st_ino  = 1;
    st.st_nlink = 1;
    st.st_size = 0;
    st.st_blksize = BLOCKLEN;
    st.st_mode = S_IFREG | 0666;
    st.st_ctime = time(NULL);
    st.st_mtime = time(NULL);
    
    entry_t *i = entry->add_entry(basename(path), &st);
    i->opened = 1;
    i->flag = META_PULLED | CHUNKED | ENCRYPT;

    i->file = new fcache(i->flag);
    i->file->chunks[0] = new fblock(0, BL_SYNCED, "x");


    fi->fh = (uint64_t)i;
    add_job((job_func)filesync, i, 60);
    entry->unlock();
    return 0;
}

int baidu_access(const char *path, int mode)
{
    return 0;
}


/*
 * 打开一个文件，如果这个文件在缓存里面存在，直接指向它，并将计数器加一
 * 如果只读打开的话，生成一个读缓存文件
 * 如果只写，读写打开，这个文件在服务器上存在的话，不行！
 * 否则，返回文件不存在
 */
int baidu_open(const char *path, struct fuse_file_info *fi) {
    entry_t* entry = getentry(path);
    if((entry->flag & CHUNKED) == 0 &&
       (fi->flags & O_ACCMODE) != O_RDONLY)
    {
        entry->unlock();
        return -EACCES;
    }
    if(entry->file){
        entry->opened++;
        fi->fh = (uint64_t)entry;
        add_job((job_func)filesync, entry, 60);
        entry->unlock();
        return 0;
    }
    assert(entry->opened == 0);

    entry->file = new fcache(entry->flag);
    ftruncate(entry->file->fd, entry->st.st_size);
    assert(((entry->flag & CHUNKED) && entry->blocklist) ||
           ((entry->flag & CHUNKED) == 0 && entry->blocklist == nullptr));
    if(entry->blocklist){
        for (int i = 0; i < json_object_array_length(entry->blocklist); ++i) {
            json_object *block = json_object_array_get_idx(entry->blocklist, i);
            const char*  name = json_object_get_string(block);
            if(name[0] == 'x'){
                entry->file->chunks[i] = new fblock(i, BL_SYNCED, name);
            }else{
                entry->file->chunks[i] = new fblock(i, 0, name);
            }
        }
    }else{
        for(size_t i = 0; i <= GetBlkNo(entry->st.st_size, entry->st.st_blksize); i++){
            entry->file->chunks[i] = new fblock(i, 0);
        }
    }
    entry->opened = 1;
    fi->fh = (uint64_t) entry;
    add_job((job_func)filesync, entry, 60);
    entry->unlock();
    return 0;
}

//下载并同步一个chunk
static bool baidu_download_chunk(fcache *file, std::string path, size_t c, size_t blksize, bool wait){
    file->lock();
    assert(file->chunks.count(c));
    fblock* fb = file->chunks[c];
    if(file->taskid.count(c) == 0 && (fb->flag & BL_SYNCED) == 0) {
        block_param *b = (block_param *) malloc(sizeof(block_param));
        b->file = file;
        b->bno = c;
        b->blksize = blksize;
        if(file->flag & CHUNKED){
            sprintf(b->path, "%s/%s", path.c_str(), fb->name.c_str());
        }else{
            strcpy(b->path, path.c_str());
        }
        file->taskid[c] = addtask((taskfunc) readblock, b, 0);
    }
    if(wait){
        task_t taskid = 0;
        if(file->taskid.count(c)){
            taskid = file->taskid[c];
        }
        file->unlock();
        waittask(taskid);
    }else{
        file->unlock();
    }
    return fb->flag & BL_SYNCED;
}

int baidu_read_e(entry_t* entry, char *buf, size_t size, off_t offset){
    assert(entry->file);
    if(offset > entry->st.st_size) {        //如果偏移超过文件长度
        errno = EFAULT;
        return -errno;
    }

    if(offset + size > (size_t)entry->st.st_size) {   //如果剩余长度不足size，则最多读到文件末尾
        size = entry->st.st_size - offset;
    }
    if(size == 0){
        return 0;
    }
    blksize_t blksize = entry->st.st_blksize;
    std::string path = entry->getcwd();
    int c = offset / blksize;  //计算一下在哪个块
    fcache* file = entry->file;
    file->lock();
    //一般读取的时候绝大部分是向后读，所以缓存下面的几个block
    for(size_t p = c; p <= GetBlkNo(entry->st.st_size, blksize); p++){
        baidu_download_chunk(file, path, p, blksize, false);
        if(file->taskid.size() >= CACHEC)
            break;
    }
    file->unlock();
    entry->unlock();
    bool synced = baidu_download_chunk(file, path, c, blksize, true);
    entry->lock();
    if(!synced){
        return -EAGAIN;
    }
    size_t len = std::min(size, GetBlkEndPointFromP(offset, blksize) - (size_t)offset);      //计算最长能读取的字节
    int ret = file->read(buf, len, offset, blksize);
    if (ret != (ssize_t)len) {                   //读取出错了
        return ret;
    }

    if (len < size) {                   //需要读取下一个block
        int tmp = baidu_read_e(entry, buf + len, size - len, offset + len);
        if (tmp < 0) {                  //调用出错
            return tmp;
        } else
            ret += tmp;
    }
    return ret;                         //成功返回
}

int baidu_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    entry_t *entry = (entry_t *) fi->fh;
    entry->lock();
    int ret =baidu_read_e(entry, buf, size, offset);
    entry->unlock();
    return ret;
}

static void baidu_upload_chunk(entry_t *entry, bool all){
    entry->file->lock();
    for (auto blk : entry->file->dirty){ //给脏block加个上传任务
        assert(blk->flag & BL_DIRTY);
        if(!all && entry->file->dirty.size() <= CACHEC/2 && time(0) - blk->atime <= 10){
            continue;
        }
        if(entry->file->taskid.count(blk->id)){
            continue;
        }
        block_param *b = (block_param *)malloc(sizeof(block_param));
        b->file = entry->file;
        b->bno = blk->id;
        b->blksize = entry->st.st_blksize;
        strcpy(b->path, entry->getcwd().c_str());
        entry->file->taskid[blk->id] = addtask((taskfunc) uploadblock, b, 0);
    }
    entry->file->unlock();
}

//截断一个文件，只能截断读缓存中的文件，因为只有这种文件是可写的
int baidu_ftruncate_e(entry_t* entry, off_t offset){
    size_t blksize = entry->st.st_blksize;
    size_t begin = std::min(entry->st.st_size, offset);
    entry->file->lock();
    bool synced = true;
    int c = GetBlkNo(begin, blksize);
    if(begin % blksize == 0){
        entry->file->chunks[c]->flag |= BL_SYNCED;
    }else{
        synced = baidu_download_chunk(entry->file, entry->getcwd(), c, blksize, true);
    }
    entry->file->unlock();
    if(!synced){
        return -EAGAIN;
    }
    int ret = entry->file->truncate(entry->st.st_size, offset, blksize);
    if(ret == 0){
        entry->flag &= ~META_PUSHED;
        entry->st.st_size = offset;
        baidu_upload_chunk(entry, false);
        entry->st.st_mtime= time(NULL);
    }
    return ret;
}

int baidu_ftruncate(const char* path, off_t offset, struct fuse_file_info *fi){
    entry_t* entry = (entry_t *) fi->fh;
    entry->lock();
    int ret = baidu_ftruncate_e(entry, offset);
    entry->unlock();
    return ret;
}

int baidu_truncate(const char* path, off_t offset) {
    entry_t *entry = getentry(path);
    if (entry) {
        int ret = baidu_ftruncate_e(entry, offset);
        entry->unlock();
        return ret;
    }
    return -ENOENT;
}

int baidu_write_e(entry_t* entry, const char *buf, size_t size, off_t offset){
    blksize_t blksize = entry->st.st_blksize;
    int c = offset / blksize;   //计算一下在哪个块
    if((entry->flag & CHUNKED) == 0){
        errno = EPERM;
        return -errno;
    }
    if(offset > entry->st.st_size) {
        baidu_ftruncate_e(entry, offset);
    }
    std::string path = entry->getcwd();
    fcache* file = entry->file;
    file->lock();
    entry->unlock();

    if(file->chunks.count(c) == 0){
        file->chunks[c] = new fblock(c, BL_SYNCED);
    }
    auto& fb = file->chunks[c];
    if(offset % blksize == 0  && size >= (size_t)blksize){
        //这里写入整个块，可以不同步，直接写入
        fb->flag |= BL_SYNCED;
    }
    file->unlock();
    bool synced = baidu_download_chunk(file, path, c, blksize, true);
    if(!synced){
        entry->lock();
        return -EAGAIN;
    }
    int len = std::min(size, GetBlkEndPointFromP(offset, blksize) - (size_t)offset);      //计算最长能写入的字节
    int ret = file->write(buf, len, offset, blksize);
    entry->lock();
    if(ret>0 && ret + offset > entry->st.st_size){
        entry->st.st_size = ret + offset;
    }
    entry->flag &= ~META_PUSHED;
    baidu_upload_chunk(entry, false);
    entry->st.st_mtime= time(NULL);
    if(ret != (ssize_t)len) {                   //读取出错了
        return ret;
    }
    if((size_t)len < size) {                   //需要读取下一个block
        int tmp = baidu_write_e(entry, buf + len, size - len, offset + len);
        if (tmp < 0) {                  //调用出错
            return tmp;
        } else
            ret += tmp;
    }
    return ret;
}
int baidu_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    entry_t* entry = (entry_t *) fi->fh;
    entry->lock();
    int ret = baidu_write_e(entry, buf, size, offset);
    entry->unlock();
    return ret;
}


static int trim(entry_t *node){
    assert(node->file);
    node->file->lock();
    if(node->file->droped.empty()){
        node->file->unlock();
        return 0;
    }
    char buff[2048];
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=delete&"
             "access_token=%s&" , Access_Token);
    std::string param = "param=";
    json_object *jobj = json_object_new_object();
    json_object *jarray = json_object_new_array();

    std::string fullpath = std::string(basepath) + node->getcwd();
    for(auto i: node->file->droped) {
        json_object *jpath = json_object_new_object();
        json_object_object_add(jpath, "path", json_object_new_string((fullpath+"/"+i).c_str()));
        json_object_array_add(jarray, jpath);
    }
    node->file->droped.clear();
    node->file->unlock();
    json_object_object_add(jobj, "list", jarray);
    param += json_object_to_json_string(jobj);
    json_object_put(jobj);

    buffstruct read_bs = {0, (size_t)param.size(), (char *)param.data()};
    Http *r = Httpinit(buff);

    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    r->method = Httprequest::post_x_www_form_urlencoded;
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

int baidu_updatemeta(entry_t *entry){
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s/meta.json", basepath, entry->getcwd().c_str());
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "path=%s&"
             "ondup=overwrite"
             , Access_Token, URLEncode(fullpath).c_str());

    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "size", json_object_new_int64(entry->st.st_size));
    json_object_object_add(jobj, "ctime", json_object_new_int64(entry->st.st_ctime));
    json_object_object_add(jobj, "mtime", json_object_new_int64(entry->st.st_mtime));
    json_object_object_add(jobj, "blksize", json_object_new_int64(entry->st.st_blksize));
    if(entry->flag & ENCRYPT){
        json_object_object_add(jobj, "encoding", json_object_new_string("xor"));
    }else{
        json_object_object_add(jobj, "encoding", json_object_new_string("none"));
    }
    json_object_object_add(jobj, "block_list", json_object_get(entry->blocklist));
    const char *jstring = json_object_to_json_string(jobj);
    buffstruct read_bs = {0, strlen(jstring), (char *)jstring};
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
    json_object_put(jobj);
    ERROR_CHECK(ret);
    free(bs.buf);
    if(trim(entry)){
        errorlog("trim failed: %s\n", fullpath);
    }
    return 0;
}


int filesync(entry_t *entry, int release){
    entry->lock();
    if(entry->file == nullptr){
        entry->flag |= META_PUSHED;
        entry->unlock();
        return 0;
    }
    if(entry->st.st_nlink == 0){
        entry->flag |= META_PUSHED;
        entry->file->unlock();
        entry->unlock();
        return 0;
    }
    entry->file->lock();
    entry->unlock();
wait:
    while(release && entry->file->taskid.size()){
        auto i = entry->file->taskid.begin();
        task_t taskid = i->second;
        entry->file->unlock();
        waittask(taskid);
        entry->file->lock();
    }

    if(entry->file->dirty.size()){
        assert(entry->flag & CHUNKED);
        baidu_upload_chunk(entry, true);
        if(release)
            goto wait;
    }else {
        entry->file->unlock();
        entry->lock();
        if((entry->flag & META_PUSHED) == 0){
            if(entry->blocklist){
                json_object_put(entry->blocklist);
            }
            entry->blocklist = json_object_new_array();
            entry->file->lock();
            for (size_t i = 0; i <= GetBlkNo(entry->st.st_size, entry->st.st_blksize); ++i) {
                assert((entry->file->chunks[i]->flag & BL_DIRTY) == 0);
                json_object_array_add(entry->blocklist, json_object_new_string(entry->file->chunks[i]->name.c_str()));
            }
            while(baidu_updatemeta(entry));
            entry->flag |= META_PUSHED;
        }
        if(release){
            entry->opened -- ;
        }
        entry->unlock();
    }
    entry->file->unlock();
    return 0;
}


int filesync(entry_t *node){
   return filesync(node, 0);
}

int baidu_fsync(const char *path, int flag, struct fuse_file_info *fi) {
    entry_t *node = (entry_t *) fi->fh;
    return filesync(node, 0);
}


int baidu_flush(const char * path, struct fuse_file_info *fi){
    return baidu_fsync(path, 0, fi);
}

/*
 * 释放一个文件
 */
int baidu_release(const char *path, struct fuse_file_info *fi) {
    entry_t *entry = (entry_t*) fi->fh;
    filesync(entry, 1);
    entry->release();
    return 0;
}

int baidu_utimens(const char *path, const struct timespec tv[2]){
    entry_t *entry = getentry(path);
    if(entry == nullptr){
        return -ENOENT;
    }
    if((entry->flag & CHUNKED) == 0){
        entry->unlock();
        return -EACCES;
    }
    entry->st.st_atim = tv[0];
    entry->st.st_mtim = tv[1];
    if(entry->opened == 0){
        while(baidu_updatemeta(entry));
    }else{
        entry->flag &= ~META_PUSHED;
    }
    entry->unlock();
    return 0;
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
    entry_t *entry = getentry(path);
    if(entry->flag & CHUNKED){
        value[0]='1';
    }else{
        value[0]='0';
    }
    entry->unlock();
    return sizeof(char);
}




