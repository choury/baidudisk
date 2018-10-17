#include <curl/curl.h>
#include <stdint.h>
#include <syslog.h>
#ifndef __NET_H__
#define __NET_H__

#ifdef __cplusplus
extern "C" {
#endif

#define errorlog(...)  fprintf(stderr, __VA_ARGS__)

typedef size_t (*CBfunc)( void *ptr, size_t size,size_t nmemb, void *stream);

typedef struct Httprequest {
    enum {head,get,post_formdata,post_x_www_form_urlencoded,Delete} method;
    const char *url;
    size_t length;
    char *range;
    char *cookies;
    char *useragent;
    uint32_t timeout;
    CBfunc readfunc;                //传送给服务器的数据
    void *readprame;
    CBfunc writefunc;               //读取服务器返回的数据
    void *writeprame;
    CURL *curl_handle;
}Http;

typedef ssize_t (*ReadFunc)(const void *source,void *buff,size_t len);
typedef ReadFunc WriteFunc;

void netinit();
Http * Httpinit(const char *url);                   //根据url生成一个Http结构体，并返回它的指针，必须用HttpDestroy销毁，不然会内存泄漏
void Httpdestroy(Http *hh); 
CURLcode request( Http *r );                        //发送请求


#ifdef __cplusplus
}
#endif

#endif
