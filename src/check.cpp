#include "baiduapi.h"
#include "utils.h"
#include "net.h"
#include <stdio.h>
#include <unistd.h>
#include <vector>
#include <set>
#include <string>
#include <string.h>
#include <assert.h>
#include <json-c/json.h>

using namespace std;

static const char *basepath = "/apps/Native";
const char* Access_Token;
bool verbose = false;
bool autofix = false;

vector<pair<string, bool>> list(const string& path){
    vector<pair<string, bool>> files;
    char buff[2048];
    char fullpath[1024];
    sprintf(fullpath, "%s%s/", basepath, path.c_str());

    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=list&"
             "limit=0-100000&"
             "by=name&"
             "order=asc&"
             "access_token=%s&"
             "path=%s"
             , Access_Token, URLEncode(fullpath).c_str());

    Http *r = Httpinit(buff);

    if (r == NULL) {
        fprintf(stderr, "can't resolve domain:%s\n", strerror(errno));
        return files;
    }

    r->method = Httprequest::get;
    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    Httpdestroy(r);
    if(ret != CURLE_OK) {
        fprintf(stderr, "network error:%d\n", ret);
        return files;
    }

    json_object *json_get = json_tokener_parse(bs.buf);

    if (json_get == NULL) {
        fprintf(stderr, "json_tokener_parse filed!\n");
        return files;
    }

    json_object *jlist;
    json_object_object_get_ex(json_get, "list",&jlist);

    for (int i = 0; i < json_object_array_length(jlist); ++i) {
        json_object *filenode = json_object_array_get_idx(jlist, i);

        json_object *jpath;
        json_object_object_get_ex(filenode, "path", &jpath);
        const char *bpath = json_object_get_string(jpath) + strlen(basepath);

        json_object *jisdir;
        json_object_object_get_ex(filenode, "isdir",&jisdir);
        if (json_object_get_boolean(jisdir)) {
            files.push_back(make_pair(bpath, true));
        } else {
            files.push_back(make_pair(bpath, false));
        }
    }
    json_object_put(json_get);
    return files;
}

set<string> readblklist(const string& path) {
    set<string> blks;
    char buff[2048];
    char fullpath[1024];
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s/meta.json", basepath, path.c_str());
    snprintf(buff, sizeof(buff) - 1,
             "https://pcs.baidu.com/rest/2.0/pcs/file?"
             "method=download&"
             "access_token=%s&"
             "path=%s",
             Access_Token, URLEncode(fullpath).c_str());

    int ret = 0;
    buffstruct bs;
    Http *r = Httpinit(buff);
    if (r == NULL) {
        errorlog("can't resolve domain:%s\n", strerror(errno));
        return blks;
    }
    r->method = Httprequest::get;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    ret = request(r);
    Httpdestroy(r);
    if (ret != CURLE_OK) {
        errorlog("network error:%d\n", ret);
        return blks;
    }

    json_object *json_get = json_tokener_parse(bs.buf);
    if (json_get == NULL) {
        errorlog("json_tokener_parse filed!\n");
        return blks;
    }

    json_object *jsize;
    json_object_object_get_ex(json_get, "size",&jsize);

    json_object *jblksize;
    json_object_object_get_ex(json_get, "blksize",&jblksize);


    json_object *jblock_list;
    json_object_object_get_ex(json_get, "block_list",&jblock_list);
    for (int i = 0; i < json_object_array_length(jblock_list); ++i) {
        json_object *block = json_object_array_get_idx(jblock_list, i);
        const char*  name = json_object_get_string(block);
        blks.insert(name);
    }
    json_object_put(json_get);
    return blks;
}

static int baidu_rm(const string& path) {
    char buff[2048];
    char fullpath[1024];
    if(verbose){
        printf("will delete file: %s\n", path.c_str());
    }
    snprintf(fullpath, sizeof(fullpath) - 1, "%s%s", basepath, path.c_str());

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
    buffstruct bs;
    r->writefunc = savetobuff;
    r->writeprame = &bs;

    int ret = request(r);
    Httpdestroy(r);
    if (ret != CURLE_OK) {
        errorlog("network error:%d\n", ret);
        return -EPROTO;
    }
    return 0;
}

void checkfile(const string& path){
    auto files = list(path);
    if(endwith(path, ".def")){
        set<string> fs;
        for(auto f: files){
            fs.insert(f.first.substr(path.size()+1));
        }
        if(fs.count("meta.json") == 0){
            fprintf(stderr, "file: %s have no meta.json\n", decodepath(path).c_str());
            return;
        }
        fs.erase("meta.json");
        auto blks = readblklist(path);
        if(blks.size() == 0){
            fprintf(stderr, "file: %s have malformed meta.json\n", decodepath(path).c_str());
            return;
        }
        blks.erase("x");
        for(auto b : blks){
            if(fs.count(b) == 0){
                fprintf(stderr, "file: %s miss block: %s\n", decodepath(path).c_str(), b.c_str());
            }
        }
        for(auto f : fs){
            if(blks.count(f) == 0){
                fprintf(stderr, "file: %s has lagecy block: %s\n", decodepath(path).c_str(), f.c_str());
                if(autofix && baidu_rm(path+"/"+f)){
                    fprintf(stderr, "delete file: %s failed\n", path.c_str());
                }
            }
        }
        if(verbose)
            printf("%s check finish\n", decodepath(path).c_str());
        return;
    }
    for(auto f: files){
        if(!f.second){
            if(verbose)
                printf("%s check ok\n", path.c_str());
            continue;
        }
        checkfile(f.first);
    }
}


int main(int argc, char** argv){
    baiduapi_init();
    Access_Token = gettoken();
    char ch;
    while((ch = getopt(argc, argv, "vf")) != -1)
    switch(ch)
    {
    case 'v':
        printf("verbose mode\n");
        verbose = true;
        break;
    case 'f':
        printf("will try fix error\n");
        autofix = true;
        break;
    }
    const char* path;
    if(argv[optind]){
        path = argv[optind];
    } else{
        path = "/";
    }
    printf("will check path: %s\n", path);
    checkfile(path);
    return 0;
}
