#include <string.h>
#include <errno.h>
#include <assert.h>

#include <unistd.h>

#include <json-c/json.h>

#include "baiduapi.h"
#include "net.h"

static const char *basepath = "/apps/Native";
static const char *sk = "wiz77wrFfUGje0oGGOaG3kOU7T18dSg2";
static const char *confpath;

static char Access_Token[100];

static int baiduapi_refreshtoken();


/*处理百度服务器返回的各种乱七八糟的错误码，转换成errno形式的
 * 只有我经常碰到的错误，并且我能对应得上的一些
 * 如果返回111,即AT过期，则刷新AT
 */
static int handleerror(const char* file, const char *msg, size_t len) {
    errorlog("%s: %.*s\n", file, (int)len, msg);
    if(msg == nullptr){
        errno = EIO;
        return -errno;
    }
    json_object *json_get = json_tokener_parse(msg);
    if (json_get == NULL) {
        errorlog("json_tokener_parse failed!\n");
        return -EPROTO;
    }

    int error = 0;
    json_object *jerror_code;
    if (json_object_object_get_ex(json_get, "error_code",&jerror_code)) {
        error = json_object_get_int(jerror_code) ;
        json_object_put(json_get);
    }else{
        json_object_put(json_get);
        errorlog("get error code failed!\n");
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
        baiduapi_refreshtoken();
        errno = EAGAIN;
        break;
    case 31021:
        errno = ENETUNREACH;
        break;

    case 31023:
        errno = EINVAL;
        break;

    case 31034:
    case 31045:
        errno = EAGAIN;
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
        
    case 31200:
        errno = EBUSY;
        break;

    case 31202:
    case 31297:
        errno = ENOENT;
        break;

    case 31212:
    case 31233:
    case 31243:
    case 31299:
    case 31811:
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
    Httpdestroy(r); \
    if(ret > CURL_LAST){ \
        ret = handleerror(__PRETTY_FUNCTION__, bs.buf, bs.offset); \
        return ret; \
    }\
    if(ret != CURLE_OK) { \
        errorlog("network error:%d\n", ret); \
        errno = EAGAIN; \
        return -EPROTO; \
    }

/*获得Access_Token
 * 我曾经把自己模拟成浏览器手动post用户名密码，开始挺好使的
 * 后来不行了……因为登录次数多了居然要输验证码了！！！
 */
static int baiduapi_gettoken(const char* confpath) {
    char code[200];
    char buff[1024];
    char ATfile[1024];
    json_object *json_get;
    ::confpath = confpath;

    sprintf(ATfile,"%s/Access_Token", confpath);
    if (!(json_get = json_object_from_file(ATfile))) {                     //如果当前目录下面没有.Access_Token文件，那么重新获取
        fprintf(stderr, "You have to login first!\n");

        printf("http://openapi.baidu.com/oauth/2.0/authorize?"
               "response_type=code&"
               "client_id=%s&"
               "redirect_uri=oob&"
               "scope=netdisk&"
               "display=page\n", API_AK);
        puts("please open the url above,and copy the authorization code from the browser:");
        scanf("%199s", code);
        sprintf(buff,
                "https://openapi.baidu.com/oauth/2.0/token?"
                "grant_type=authorization_code&"
                "code=%s&"
                "client_id=%s&"
                "client_secret=%s&"
                "redirect_uri=oob"
                , code, API_AK, sk);

        Http *r = Httpinit(buff);
        r->method = Httprequest::get;
        buffstruct bs;
        r->writefunc = savetobuff;
        r->writeprame = &bs;

        int ret = request(r);
        ERROR_CHECK(ret);
        json_get = json_tokener_parse(bs.buf);
        if (json_get == NULL) {
            errorlog("json_tokener_parse failed!\n");
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
            return -EPERM;
        }
    } else {            //如果文件里面存在，直接读取文件，当然，这里没有考虑有不怀好意的人修改我的文件的情况
        json_object *jaccess_token;
        json_object_object_get_ex(json_get, "access_token",&jaccess_token);
        strcpy(Access_Token, json_object_get_string(jaccess_token));
        json_object_put(json_get);
    }
    return 0;
}

static int baiduapi_refreshtoken() {
    char buff[1024];
    char ATfile[1024];
    char Refresh_Token[100];
    json_object *json_get;

    sprintf(ATfile,"%s/Access_Token",confpath);
    if (!(json_get = json_object_from_file(ATfile))) {            //如果当前目录下面没有.Access_Token文件，那么直接调用gettoken
        return baiduapi_gettoken(confpath);
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
                 "client_secret=%s", Refresh_Token, API_AK, sk);
        FILE *tpfile = tmpfile();

        if (!tpfile) {
            int lasterrno = errno;
            errorlog("create temp file error:%s\n", strerror(errno));
            return -lasterrno;
        }

        Http *r = Httpinit(buff);
        r->method = Httprequest::get;
        buffstruct bs;
        r->writefunc = savetobuff;
        r->writeprame = &bs;

        int ret = request(r);
        ERROR_CHECK(ret);

        json_get = json_tokener_parse(bs.buf);

        if (json_get == NULL) {
            errorlog("json_tokener_parse failed!\n");
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

void baiduapi_prepare(){
    netinit();
    setCOFPATH();
    while(baiduapi_gettoken(COFPATH));
}


//从服务器读一个block
int baiduapi_download(const char* path, size_t startp, size_t len, buffstruct& bs) {
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=download&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath).c_str());
    bs.offset = 0;
    Http *r = Httpinit(buff);
    r->method = Httprequest::get;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    char range[100] = {0};
    if(len){
        snprintf(range, sizeof(range) - 1, "%zu-%lu", startp, startp + len - 1);
        r->range = range;
        r->timeout = std::max(len/(5*1024), (size_t)60); //不得小于5K/s
    }

    int ret = request(r);
    ERROR_CHECK(ret);
    return 0;
}

int baiduapi_upload(const char* path, const char* input, size_t len, bool overwrite, char outpath[PATHLEN]) {
    char buff[1024];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);
    if(overwrite){
        snprintf(buff, sizeof(buff) - 1,
                "https://pcs.baidu.com/rest/2.0/pcs/file?"
                "method=upload&"
                "access_token=%s&"
                "path=%s&"
                "ondup=overwrite"
                , Access_Token, URLEncode(fullpath).c_str());
    }else{
        snprintf(buff, sizeof(buff) - 1,
                "https://pcs.baidu.com/rest/2.0/pcs/file?"
                "method=upload&"
                "access_token=%s&"
                "path=%s&"
                "ondup=newcopy"
                , Access_Token, URLEncode(fullpath).c_str());
    }
    buffstruct read_bs((const char*)input, len);
    Http *r = Httpinit(buff);
    r->method = Httprequest::post_formdata;
    r->readfunc = readfrombuff;
    r->readprame = &read_bs;
    r->length = read_bs.len;

    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;
    r->timeout = std::max(len/(2*1024), (size_t)60); //不得小于2K/s

    int ret = request(r);
    ERROR_CHECK(ret);

    json_object * json_get = json_tokener_parse(bs.buf);
    if (json_get == NULL) {
        errorlog("json_tokener_parse failed!\n");
        return -EPROTO;
    }

    json_object *jpath;
    if (json_object_object_get_ex(json_get, "path", &jpath)) {
        strcpy(outpath, json_object_get_string(jpath) + strlen(basepath));
        json_object_put(json_get);
        return 0;
    } else {
        errorlog("Did not get path:%s\n", json_object_to_json_string(json_get));
        return -EPROTO;
    }
}


int baiduapi_list(const char* path, size_t limit, std::map<std::string, struct stat>& stmap){
    char buff[2048];
    char fullpath[PATHLEN];
    sprintf(fullpath, "%s%s", basepath, path);

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=list&"
             "limit=0-%zu&"
             "by=time&"
             "order=desc&"
             "access_token=%s&"
             "path=%s"
             , limit, Access_Token, URLEncode(fullpath).c_str());

    Http *r = Httpinit(buff);
    r->method = Httprequest::get;
    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    ERROR_CHECK(ret);

    json_object *json_get = json_tokener_parse(bs.buf);

    if (json_get == NULL) {
        errorlog("json_tokener_parse failed!\n");
        return -EPROTO;
    }

    json_object *jlist;
    ret = json_object_object_get_ex(json_get, "list", &jlist);
    assert(ret);

    for (int i = 0; i < json_object_array_length(jlist); ++i) {
        struct stat st;
        memset(&st, 0, sizeof(struct stat));
        st.st_nlink = 1;
        json_object *filenode = json_object_array_get_idx(jlist, i);

        json_object *jmtime;
        ret = json_object_object_get_ex(filenode, "mtime",&jmtime);
        assert(ret);
        st.st_mtime = json_object_get_int64(jmtime);

        json_object *jctime;
        ret = json_object_object_get_ex(filenode, "ctime",&jctime);
        assert(ret);
        st.st_ctime = json_object_get_int64(jctime);

        json_object *jfs_id;
        ret = json_object_object_get_ex(filenode, "fs_id",&jfs_id);
        assert(ret);
        st.st_ino = json_object_get_int64(jfs_id);

        json_object *jsize;
        ret = json_object_object_get_ex(filenode, "size",&jsize);
        assert(ret);
        st.st_size = json_object_get_int64(jsize);
        st.st_blksize = BLOCKLEN;

        json_object *jisdir;
        ret = json_object_object_get_ex(filenode, "isdir",&jisdir);
        assert(ret);
        if (json_object_get_boolean(jisdir)) {
            st.st_mode = S_IFDIR | 0755;
        } else {
            st.st_mode = S_IFREG | 0444;
        }

        json_object *jpath;
        ret = json_object_object_get_ex(filenode, "path", &jpath);
        assert(ret);
        const char *bpath = json_object_get_string(jpath) + strlen(basepath);
        stmap[bpath] = st;
    }
    json_object_put(json_get);
    return 0;
}


//获得文件属性……
int baiduapi_getattr(const char *path, struct stat *st) {
    memset(st, 0, sizeof(struct stat));
    st->st_nlink = 1;

    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=meta&"
             "access_token=%s&"
             "path=%s",
             Access_Token, URLEncode(fullpath).c_str());

    Http *r = Httpinit(buff);
    r->method = Httprequest::get;
    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    ERROR_CHECK(ret);

    json_object *json_get = json_tokener_parse(bs.buf);
    if (json_get == NULL) {
        errorlog("json_tokener_parse failed!\n");
        return -EPROTO;
    }

    json_object* jlist;
    ret = json_object_object_get_ex(json_get, "list",&jlist);
    assert(ret);
    json_object* filenode = json_object_array_get_idx(jlist, 0);

    json_object *jmtime;
    ret = json_object_object_get_ex(filenode, "mtime",&jmtime);
    assert(ret);
    st->st_mtim.tv_sec = json_object_get_int64(jmtime);

    json_object *jctime;
    ret = json_object_object_get_ex(filenode, "ctime",&jctime);
    assert(ret);
    st->st_ctim.tv_sec = json_object_get_int64(jctime);

    json_object *jfs_id;
    ret = json_object_object_get_ex(filenode, "fs_id",&jfs_id);
    assert(ret);
    st->st_ino = json_object_get_int64(jfs_id);

    json_object *jsize;
    ret = json_object_object_get_ex(filenode, "size",&jsize);
    assert(ret);
    st->st_size = json_object_get_int64(jsize);
    st->st_blksize = BLOCKLEN;

    json_object *jisdir;
    ret = json_object_object_get_ex(filenode, "isdir",&jisdir);
    assert(ret);
    if (json_object_get_boolean(jisdir)) {
        st->st_mode = S_IFDIR | 0755;                        //文件：只读，想要写，对不起，先拷贝一份下来，然后覆盖
    } else {
        st->st_mode = S_IFREG | 0444;
    }
    json_object_put(json_get);
    return 0;
}


//获得文件系统信息，对于百度网盘来说，只有容量是有用的……
int baiduapi_statfs(const char *path, struct statvfs *sf) {
    char buff[1025];
    sprintf(buff,
            "https://pcs.baidu.com/rest/2.0/pcs/quota?"
            "method=info&"
            "access_token=%s", Access_Token);

    Http *r = Httpinit(buff);
    r->method = Httprequest::get;
    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    ERROR_CHECK(ret);

    json_object *json_get = json_tokener_parse(bs.buf);

    if (json_get == NULL) {
        errorlog("json_tokener_parse failed!\n");
        return -EPROTO;
    }

    sf->f_bsize = 1;
    sf->f_frsize = 1;
    
    json_object *jquota;
    ret = json_object_object_get_ex(json_get, "quota", &jquota);
    assert(ret);
    sf->f_blocks = json_object_get_int64(jquota);
    
    json_object *jused;
    ret = json_object_object_get_ex(json_get, "used", &jused);
    assert(ret);
    sf->f_bavail = sf->f_blocks - json_object_get_int64(jused);
    sf->f_bfree = sf->f_bavail;
    json_object_put(json_get);
    return 0;
}


//自猜
int baiduapi_mkdir(const char *path, struct stat* st) {
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
    r->method = Httprequest::get;
    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    ERROR_CHECK(ret);

    json_object *json_get = json_tokener_parse(bs.buf);

    if (json_get == NULL) {
        errorlog("json_tokener_parse failed!\n");
        return -EPROTO;
    }

    memset(st, 0, sizeof(struct stat));
    st->st_nlink = 1;
    json_object *jfs_id;
    ret = json_object_object_get_ex(json_get, "fs_id",&jfs_id);
    assert(ret);
    st->st_ino = json_object_get_int64(jfs_id);
    
    json_object *jmtime;
    ret = json_object_object_get_ex(json_get, "mtime",&jmtime);
    assert(ret);
    st->st_mtime = json_object_get_int64(jmtime);
    
    json_object *jctime;
    ret = json_object_object_get_ex(json_get, "ctime",&jctime);
    assert(ret);
    st->st_ctime = json_object_get_int64(jctime);
    
    st->st_mode = S_IFDIR | 0755;
    json_object_put(json_get);
    return 0;
}


//删除文件
int baiduapi_delete(const char *path) {
    char buff[2048];
    char fullpath[PATHLEN];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path);
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=delete&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath).c_str());

    Http *r = Httpinit(buff);
    r->method = Httprequest::get;
    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    ERROR_CHECK(ret);
    return 0;
}


int baiduapi_batchdelete(std::set<std::string> flist){
retry:
    char buff[2048];
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=delete&"
             "access_token=%s&" , Access_Token);
    std::string param = "param=";
    json_object *jobj = json_object_new_object();
    json_object *jarray = json_object_new_array();

    for(auto i =  flist.begin(); i != flist.end();) {
        json_object *jpath = json_object_new_object();
        char path[PATHLEN];
        sprintf(path, "%s/%s", basepath, i->c_str());
        json_object_object_add(jpath, "path", json_object_new_string(path));
        json_object_array_add(jarray, jpath);
        i = flist.erase(i);
        if(json_object_array_length(jarray) == 200){
            break;
        }
    }
    json_object_object_add(jobj, "list", jarray);
    param += json_object_to_json_string(jobj);
    json_object_put(jobj);

    buffstruct read_bs(param.data(), (size_t)param.size());
    Http *r = Httpinit(buff);
    r->method = Httprequest::post_x_www_form_urlencoded;
    r->readfunc = readfrombuff;
    r->readprame = &read_bs;
    r->length = read_bs.len;

    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    ERROR_CHECK(ret);
    if(!flist.empty()){
        goto retry;
    }
    return 0;
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
             , Access_Token, URLEncode(oldfullpath).c_str(), URLEncode(newfullpath).c_str());

    Http *r = Httpinit(buff);
    r->method = Httprequest::get;
    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;
    int ret = request(r);
    ERROR_CHECK(ret);
    return 0;
}
