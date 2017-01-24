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
    blksize_t blksize;
    char path[PATHLEN];
} task_param;


//从服务器读一个block
void readblock(task_param *tp) {
    task_param param = *tp;
    free(tp);
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
    char *buf = nullptr;
    do{
        
        Http *r = Httpinit(buff);
        if (r == NULL) {
            errorlog("can't resolve domain:%s\n", strerror(errno));
            break;
        }
        
        r->method = Httprequest::get;
        
        buf = (char *)malloc(param.blksize);
        buffstruct bs = {0, (size_t)param.blksize, buf};
        r->writefunc = savetobuff;
        r->writeprame = &bs;
        r->timeout = param.blksize/(10*1024);
        
        char range[100] = {0};
        if((param.node->flag & CHUNKED) == 0){
            snprintf(range, sizeof(range) - 1, "%lu-%lu", startp, startp + param.blksize - 1);
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
        assert(bs.offset <= (size_t)param.blksize);
        assert(bs.buf == buf);
/*
        if(b.node->flag & CHUNKED)
            xorcode(bs.buf, startp, bs.offset, ak);
*/
        
        param.node->file->lock();
        pwrite(param.node->file->fd, bs.buf, bs.offset, startp);
        param.node->file->chunks[param.bno].flag |= BL_SYNCED;
        param.node->file->unlock();
    }while(0);
    free(buf);
    param.node->file->lock();
    param.node->file->taskid.erase(param.bno);
    param.node->file->unlock();
}

//上传一个block作为chunkfile
void uploadblock(task_param *tp) {
    task_param param = *tp;
    free(tp);
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

    char *buf = nullptr;
    do{
        Http *r = Httpinit(buff);

        if (r == NULL) {
            errorlog("can't resolve domain:%s\n", strerror(errno));
            break;
        }

        buf = (char *)malloc(param.blksize);
        buffstruct read_bs = {0, (size_t)param.blksize, buf};
        param.node->file->lock();
        if((param.node->file->chunks.count(param.bno)) == 0){ //it was truncated
            param.node->file->unlock();
            break;
        }
        assert(param.node->file->chunks[param.bno].flag & BL_DIRTY);
        assert((param.node->file->chunks[param.bno].flag & BL_TRANS) == 0);
        param.node->file->chunks[param.bno].flag |= BL_TRANS;
        read_bs.len = pread(param.node->file->fd, read_bs.buf, read_bs.len, param.bno*param.blksize);
        param.node->file->unlock();

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
        r->timeout = param.blksize/(10*1024);

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
            param.node->file->synced(param.bno, json_object_get_string(jpath)+strlen(fullpath)+1);
            json_object_put(json_get);
        } else {
            errorlog("Did not get path:%s\n", json_object_to_json_string(json_get));
        }
    }while(0);
    free(buf);
    param.node->file->lock();
    param.node->file->taskid.erase(param.bno);
    param.node->file->chunks[param.bno].flag &= ~BL_REOPEN;
    param.node->file->chunks[param.bno].flag &= ~BL_TRANS;
    param.node->file->unlock();
}

int readchunkattr(task_param *tp) {
    task_param param = *tp;
    free(tp);
    assert(endwith(param.path, ".def") == 0);
    std::string realpath = encodepath(param.path);
    std::string bname = basename(param.path);
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s/meta.json", basepath, realpath.c_str());
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=download&"
             "access_token=%s&"
             "path=%s",
             Access_Token, URLEncode(fullpath).c_str());

    int ret = 0;
    do{
        Http *r = Httpinit(buff);
        if (r == NULL) {
            ret = -errno;
            errorlog("can't resolve domain:%s\n", strerror(errno));
            break;
        }
        r->method = Httprequest::get;
        buffstruct bs = {0, 0, 0};
        r->writefunc = savetobuff;
        r->writeprame = &bs;
        
        
        ret = request(r);
        Httpdestroy(r);
        if(ret > CURL_LAST){
            ret = handleerror(bs.buf);
            free(bs.buf);
            break;
        }
        if (ret != CURLE_OK) {
            errorlog("network error:%d\n", ret);
            free(bs.buf);
            ret = -EPROTO;
            break;
        }
        
        json_object *json_get = json_tokener_parse(bs.buf);
        free(bs.buf);
        
        if (json_get == NULL) {
            errorlog("json_tokener_parse filed!\n");
            ret = -EPROTO;
            break;
        }
        
        assert(param.node->dir->entry.count(bname));
        assert(param.node->dir->entry[bname] == nullptr);
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
        
        json_object *jblock_list;
        json_object_object_get_ex(json_get, "block_list",&jblock_list);
        
        st.st_mode = S_IFREG | 0666;
        
        inode_t* node = param.node->add_entry(bname, &st);
        node->blocklist = json_object_get(jblock_list);
        node->flag |= CHUNKED;
        json_object_put(json_get);
    }while(0);
    param.node->dir->lock();
    assert(param.node->dir->taskid.count(bname));
    param.node->dir->taskid.erase(bname);
    param.node->dir->unlock();
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

//获得文件属性……
int baidu_getattr(const char *path, struct stat *st) {
    if(strcmp(path, "/") == 0){
        st->st_nlink = 1;
        st->st_mode = S_IFDIR | 0755;
        return 0;
    }
    struct fuse_file_info fi;
    int ret = baidu_opendir(dirname(path).c_str(), &fi);
    if(ret){
        return ret;
    }
    std::string bname = basename(path);
    inode_t* node = getnode(dirname(path).c_str());
    assert(node->flag & SYNCED);
    node->dir->lock();
    node->unlock();
    if(node->dir->taskid.count(bname)){
        task_t taskid = node->dir->taskid[bname];
        node->dir->unlock();
        waittask(taskid);
        node->dir->lock();
    }
    if(node->dir->entry.count(bname)){
        if(node->dir->entry[bname] == nullptr){
            task_param *b = (task_param *)malloc(sizeof(task_param));
            b->node =  node;
            strcpy(b->path, path);
            node->dir->taskid[bname] = addtask((taskfunc)readchunkattr, b, 0);
            node->dir->unlock();
            return -EAGAIN;
        }
        *st = node->dir->entry[bname]->st;
        node->dir->unlock();
        return 0;
    }else{
        node->dir->unlock();
        return -ENOENT;
    }
}

int baidu_fgetattr(const char* path, struct stat* st, struct fuse_file_info* fi){
    inode_t *node = (inode_t*)fi->fh;
    node->lock();
    memcpy(st, &node->st, sizeof(struct stat));
    node->unlock();
    return 0;
}

int baidu_opendir(const char *path, struct fuse_file_info *fi){
    inode_t* node = getnode(path);
    assert(node->file == nullptr);
    fi->fh = (uint64_t)node;
    if(node->flag & SYNCED){
        node->unlock();
        return 0;
    }
    node->unlock();
    assert(node->dir);
    char buff[2048];
    char fullpath[PATHLEN];
    sprintf(fullpath, "%s%s/", basepath, path);

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
    node->dir->lock();
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
        json_object_object_get_ex(filenode, "path",&jpath);
        const char *bpath = json_object_get_string(jpath) + strlen(basepath);
        if(endwith(bpath, ".def")){
            std::string realpath = decodepath(bpath);
            if(node->dir->entry.count(basename(realpath)) && node->dir->entry[basename(realpath)]){
                continue;
            }
            node->dir->entry[basename(realpath)] = nullptr;
            task_param *b = (task_param *)malloc(sizeof(task_param));
            b->node =  node;
            strcpy(b->path, realpath.c_str());
            node->dir->taskid[basename(realpath)] = addtask((taskfunc)readchunkattr, b, 0);
        }else{
            node->add_entry(basename(bpath), &st);
        }
    }
    json_object_put(json_get);
    node->dir->unlock();
    node->flag |= SYNCED;
    node->flag |= DIRTY;
    node->unlock();
    return 0;
}

//读取目录下面有什么文件
int baidu_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    (void) offset;
    inode_t* node = (inode_t *)fi->fh;
    node->lock();
    assert(node->file == nullptr);
    node->dir->lock();
    while(!node->dir->taskid.empty()){
        task_t taskid = node->dir->taskid.begin()->second;
        node->dir->unlock(); 
        waittask(taskid);
        node->dir->lock();
    }
    for(auto i:node->dir->entry){
        if(i.second == nullptr){
            task_param *b = (task_param *)malloc(sizeof(task_param));
            b->node =  node;
            sprintf(b->path, "%s/%s", path, i.first.c_str());
            node->dir->taskid[i.first] = addtask((taskfunc)readchunkattr, b, 0);
        }
    }
    node->filldir(buf, filler);
    node->dir->unlock();
    node->unlock();
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
    
    inode_t *node = getnode(dirname(path).c_str());
    node->add_entry(basename(path), &st)->flag |= SYNCED;
    node->unlock();
    return 0;
}


//删除文件（文件夹需使用rmdir）
int baidu_unlink(const char *path) {
    inode_t* node = getnode(path);
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
    inode_t* node = getnode(path);
    if(node){
        if(node->flag & SYNCED){
            assert(node->file == nullptr);
            if(!node->empty()){
                node->unlock();
                return -ENOTEMPTY;
            }else{
                node->unlock();
                return baidu_unlink(path);
            }
        }
        node->unlock();
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
    inode_t *node = getnode(oldname);
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

    Http *r = Httpinit(buff);
    if (r == NULL) {
        int lasterrno = errno;
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return -lasterrno;
    }

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=delete&"
             "access_token=%s&"
             "path=%s"
             , Access_Token,  URLEncode(newfullpath).c_str());

    r->method = Httprequest::get;
    buffstruct bs = {0, 0, 0};
    r->writefunc = savetobuff;
    r->writeprame = &bs;
    request(r);

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=move&"
             "access_token=%s&"
             "from=%s&"
             "to=%s"
             , Access_Token, URLEncode(oldfullpath).c_str(), URLEncode(newfullpath).c_str());
    
    bs.offset = 0;

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
    inode_t *node = getnode(dirname(path).c_str());
    assert(node->file == nullptr);
    
    struct stat st;
    memset(&st, 0, sizeof(struct stat));
    st.st_ino  = 1;
    st.st_nlink = 1;
    st.st_size = 0;
    st.st_blksize = BLOCKLEN;
    st.st_mode = S_IFREG | 0666;
    st.st_ctime = time(NULL);
    st.st_mtime = time(NULL);
    
    inode_t *i = node->add_entry(basename(path), &st);
    
    i->file = new fcache();
    i->opened = 1;
    i->flag |= CHUNKED;
    i->flag |= DIRTY;

    fi->fh = (uint64_t)i;
    add_job((job_func)filesync, i, 60);
    node->unlock();
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
    inode_t* node = getnode(path);
    if((node->flag & CHUNKED) == 0 &&
       (fi->flags & O_ACCMODE) != O_RDONLY)
    {
        node->unlock();
        return -EACCES;
    }
    if(node->file){
        node->opened++;
        fi->fh = (uint64_t)node;
        node->unlock();
        return 0;
    }
    assert(node->opened == 0);

    node->file = new fcache();
    ftruncate(node->file->fd, node->st.st_size);
    assert(((node->flag & CHUNKED) && node->blocklist) ||
           ((node->flag & CHUNKED) == 0 && node->blocklist == nullptr));
    if(node->blocklist){
        for (int i = 0; i < json_object_array_length(node->blocklist); ++i) {
            json_object *block = json_object_array_get_idx(node->blocklist, i);
            node->file->chunks[i].name = json_object_get_string(block);
            if(node->file->chunks[i].name == "x"){
                node->file->chunks[i].flag |= BL_SYNCED;
            }
        }

    }
    node->opened = 1;
    fi->fh = (uint64_t) node;
    add_job((job_func)filesync, node, 60);
    node->unlock();
    return 0;
}




//读
int baidu_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    inode_t *node = (inode_t *) fi->fh;
    node->lock();
    assert(node->file);
    if (offset > node->st.st_size) {        //如果偏移超过文件长度
        node->unlock();
        errno = EFAULT;
        return -errno;
    }

    if (offset + size > (size_t)node->st.st_size) {   //如果剩余长度不足size，则最多读到文件末尾
        size = node->st.st_size - offset;
    }
    if(size == 0){
        node->unlock();
        return 0;
    }
    blksize_t blksize = node->st.st_blksize;
    int c = offset / blksize;  //计算一下在哪个块
    size_t p = c;
    node->file->lock();
    do{             //一般读取的时候绝大部分是向后读，所以缓存下面的几个block
        if(p > GetBlkNo(node->st.st_size, node->st.st_blksize)){
            break;
        }
        if (node->file->taskid.count(p) == 0 &&
            (node->file->chunks[p].flag & BL_SYNCED) == 0)
        {
            task_param *b = (task_param *) malloc(sizeof(task_param));
            b->node = node;
            b->bno = p;
            b->blksize = node->st.st_blksize;
            if(node->flag & CHUNKED){
                sprintf(b->path, "%s/%s", node->getcwd().c_str(), node->file->chunks[p].name.c_str());
            }else{
                strcpy(b->path, node->getcwd().c_str());
            }
            node->file->taskid[p] = addtask((taskfunc) readblock, b, 0);
            node->flag &= ~SYNCED;
        }
        p++;
    }while (node->file->taskid.size() < CACHEC);
    node->file->unlock();
    node->unlock();
    size_t len = std::min(size, GetBlkEndPointFromP(offset, blksize) - offset);      //计算最长能读取的字节
    int ret = node->file->read(buf, len, offset, blksize);
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

//截断一个文件，只能截断读缓存中的文件，因为只有这种文件是可写的
int baidu_ftruncate(const char* path, off_t offset, struct fuse_file_info *fi){
    inode_t* node = (inode_t *) fi->fh;
    node->lock();
    int ret = node->file->truncate(node->st.st_size, offset, node->st.st_blksize);
    if(ret == 0){
        node->flag &= ~SYNCED;
        node->flag |= DIRTY;
        node->st.st_size = offset;
        node->file->lock();
        for (size_t i = 0; i < GetBlkNo(node->st.st_size, node->st.st_blksize); ++i) {
            if (node->file->taskid.count(i) == 0 &&
                (node->file->chunks[i].flag & BL_DIRTY) &&
                time(0) - node->file->chunks[i].atime >= 10 )              //如果这个block是脏的那么加个上传任务
            {
                task_param *b = (task_param *)malloc(sizeof(task_param));
                b->node = node;
                b->bno = i;
                b->blksize = node->st.st_blksize;
                strcpy(b->path, node->getcwd().c_str());
                node->file->taskid[i] = addtask((taskfunc) uploadblock, b, 0);
            }
        }
        node->file->unlock();
        node->st.st_mtime= time(NULL);
    }
    node->unlock();
    return ret;
}

int baidu_truncate(const char* path, off_t offset) {
    inode_t *node = getnode(path);
    if (node) {
        node->unlock();
        struct fuse_file_info fi;
        fi.fh = (uint64_t)node;
        return baidu_ftruncate(path, offset, &fi);
    }
    return -ENOENT;
}

int baidu_write(const char *path, const char *buf, size_t size, off_t offset, struct fuse_file_info *fi)
{
    inode_t* node = (inode_t *) fi->fh;
    node->lock();
    blksize_t blksize = node->st.st_blksize;
    int c = offset / blksize;   //计算一下在哪个块
    if(node->file == nullptr || (node->flag & CHUNKED) == 0){
        node->unlock();
        errno = EPERM;
        return errno;
    }
    if(offset > node->st.st_size) {
        baidu_ftruncate(path, offset, fi);
    }
    node->file->lock();
    node->unlock();
    if (node->file->chunks.count(c) && node->st.st_size){
        if(node->file->taskid.count(c) == 0 &&
           (node->file->chunks[c].flag & BL_SYNCED) == 0)
        {
            task_param *b = (task_param *) malloc(sizeof(task_param));
            b->node = node;
            b->bno = c;
            b->blksize = node->st.st_blksize;
            sprintf(b->path, "%s/%s", node->getcwd().c_str(), node->file->chunks[c].name.c_str());
            node->file->taskid[c] = addtask((taskfunc) readblock, b, 0);
        }
        task_t taskid = 0;
        if(node->file->taskid.count(c)){
            taskid = node->file->taskid[c];
        }
        node->file->unlock();
        waittask(taskid);
        node->file->lock();
        if((node->file->chunks[c].flag & BL_SYNCED) == 0){
            node->file->unlock();
            return -EAGAIN;
        }
    }
    node->file->unlock();
    int len = std::min(size, GetBlkEndPointFromP(offset, blksize) - offset);      //计算最长能写入的字节
    int ret = node->file->write(buf, len, offset, blksize);
    node->lock();
    if(ret>0 && ret + offset > node->st.st_size){
        node->st.st_size = ret + offset;
    }
    node->flag &= ~SYNCED;
    node->flag |= DIRTY;
    node->file->lock();
    for (size_t i = 0; i < GetBlkNo(node->st.st_size, node->st.st_blksize); ++i) {
        if (node->file->taskid.count(i) == 0 &&
            (node->file->chunks[i].flag & BL_DIRTY) &&
            time(0) - node->file->chunks[i].atime >= 10)              //如果这个block是脏的那么加个上传任务
        {
            task_param *b = (task_param *)malloc(sizeof(task_param));
            b->node = node;
            b->bno = i;
            b->blksize = node->st.st_blksize;
            strcpy(b->path, node->getcwd().c_str());
            node->file->taskid[i] = addtask((taskfunc) uploadblock, b, 0);
        }
    }
    node->file->unlock();
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


int trim(inode_t *node){
    del_job((job_func)trim, node);
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

int baidu_updatemeta(inode_t *node){
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s/meta.json", basepath, node->getcwd().c_str());
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=upload&"
             "access_token=%s&"
             "path=%s&"
             "ondup=overwrite"
             , Access_Token, URLEncode(fullpath).c_str());

    json_object *jobj = json_object_new_object();
    json_object_object_add(jobj, "size", json_object_new_int64(node->st.st_size));
    json_object_object_add(jobj, "ctime", json_object_new_int64(node->st.st_ctime));
    json_object_object_add(jobj, "mtime", json_object_new_int64(node->st.st_mtime));
    json_object_object_add(jobj, "blksize", json_object_new_int64(node->st.st_blksize));
    json_object_object_add(jobj, "encoding", json_object_new_string("none"));
    json_object_object_add(jobj, "block_list", json_object_get(node->blocklist));
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
    add_job((job_func)trim, node, 0);
    return 0;
}


int filesync(inode_t *node, int sync_meta){
    node->lock();
    if(node->flag & SYNCED ||node->file == nullptr || node->st.st_nlink == 0){
        node->unlock();
        node->flag |= SYNCED;
        return 0;
    }
    node->file->lock();
    while(sync_meta && node->file->taskid.size()){
        task_t taskid = node->file->taskid.begin()->second;
        node->file->unlock();
        waittask(taskid);
        node->file->lock();
    }
    if((node->flag & CHUNKED)){
        while(node->flag & DIRTY){
            node->flag &= ~DIRTY;
            std::set<task_t> waitset;
            for (size_t i = 0; i <= GetBlkNo(node->st.st_size, node->st.st_blksize); ++i) {
                if (node->file->taskid.count(i)) {
                    waitset.insert(node->file->taskid[i]);
                }else if (node->st.st_nlink && (node->file->chunks[i].flag & BL_DIRTY)) {
                    task_param *b = (task_param *)malloc(sizeof(task_param));
                    b->node =  node;
                    b->bno = i;
                    b->blksize = node->st.st_blksize;
                    strcpy(b->path, node->getcwd().c_str());
                    task_t taskid = addtask((taskfunc) uploadblock, b, 0);
                    node->file->taskid[i] = taskid;
                    waitset.insert(taskid);
                    node->flag |= DIRTY;
                }
            }
            if(!sync_meta){
                break;
            }
            node->file->unlock();
            for(auto i:waitset){
                waittask(i);
            }
            node->file->lock();
        }
        if(sync_meta && (node->flag & SYNCED) == 0){
            if(node->blocklist){
                json_object_put(node->blocklist);
            }
            node->blocklist = json_object_new_array();
            for (size_t i = 0; i <= GetBlkNo(node->st.st_size, node->st.st_blksize); ++i) {
                json_object_array_add(node->blocklist, json_object_new_string(node->file->chunks[i].name.c_str()));
            }
            while (baidu_updatemeta(node));
            node->flag |= SYNCED;
        }
    }else{
        node->flag |= SYNCED;
    }
    node->file->unlock();
    node->unlock();
    return 0;
}


int filesync(inode_t *node){
   return filesync(node, 0);
}

int baidu_fsync(const char *path, int flag, struct fuse_file_info *fi) {
    inode_t *node = (inode_t *) fi->fh;
    return filesync(node, flag);
}


int baidu_flush(const char * path, struct fuse_file_info *fi){
    return baidu_fsync(path, 0, fi);
}

/*
 * 释放一个文件
 */
int baidu_release(const char *path, struct fuse_file_info *fi) {
    inode_t *node = (inode_t*) fi->fh;
    filesync(node, 1);
    node->release();
    return 0;
}

int baidu_utimens(const char *path, const struct timespec tv[2]){
    inode_t *node = getnode(path);
    if(node == nullptr){
        return -ENOENT;
    }
    if((node->flag & CHUNKED) == 0){
        node->unlock();
        return -EACCES;
    }
    node->st.st_atim = tv[0];
    node->st.st_mtim = tv[1];
    if(node->opened == 0){
        while(baidu_updatemeta(node));
    }else{
        node->flag &= ~SYNCED;
    }
    node->unlock();
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
    inode_t *node = getnode(path);
    if(node->flag & CHUNKED){
        value[0]='1';
    }else{
        value[0]='0';
    }
    node->unlock();
    return sizeof(char);
}




