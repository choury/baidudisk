#include <curl/curl.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <assert.h>

#include "net.h"

//用来存放已有的CURL的链表
struct connect_data{
    CURL *handle;
    struct connect_data* next;
};

static struct connect_data* conhead;                             //链表头指针
static pthread_mutex_t lockcon;                         //操作那个链表使用的锁


static pthread_mutex_t *lockarray;                      //这个锁用来openssl多线程操作互斥

int(*errorlog)( const char *__restrict fmt, ... );


static void lock_callback(int mode, int type,const char *file, int line){
   (void)file;
   (void)line;

    if(mode & CRYPTO_LOCK){
        pthread_mutex_lock(&( lockarray[type]));
    } else {
        pthread_mutex_unlock(&( lockarray[type]));
    }
}

static unsigned long thread_id(void){
    unsigned long ret;

    ret =(unsigned long)pthread_self();
    return(ret);
}


static void init_locks(void){
    int i;
    lockarray =(pthread_mutex_t *)OPENSSL_malloc( CRYPTO_num_locks()*
                sizeof(pthread_mutex_t));

    for(i = 0; i < CRYPTO_num_locks(); i++){
        pthread_mutex_init(&( lockarray[i]), NULL );
    }

    CRYPTO_set_id_callback(thread_id);
    CRYPTO_set_locking_callback(lock_callback);
}



struct data {
    char trace_ascii; /* 1 or 0 */
};


//下面个函数来自于curl的文档，调试用（包括上面那个结构体)
static void dump(const char *text,
                  FILE *stream, unsigned char *ptr, size_t size,
                  char nohex){
    size_t i;
    size_t c;

    unsigned int width = 0x10;

    if(nohex)
        /* without the hex output, we can fit more on screen */
        width = 0x40;

    fprintf(stream, "%s, %10.10ld bytes(0x%8.8lx)\n",
             text,(long)size, ( long )size );

    for(i = 0; i < size; i += width){

        fprintf(stream, "%4.4lx: ",( long)i );

        if(!nohex){
            /* hex not disabled, show it */
            for(c = 0; c < width; c++)
                if(i + c < size)
                    fprintf(stream, "%02x ", ptr[i + c]);
                else
                    fputs("   ", stream);
        }

        for(c = 0; ( c < width)&& ( i + c < size ); c++ ) {
            /* check for 0D0A; if found, skip past and start a new line of output */
            if(nohex && ( i + c + 1 < size)&& ptr[i + c] == 0x0D && ptr[i + c + 1] == 0x0A ) {
                i +=(c + 2 - width);
                break;
            }

            fprintf(stream, "%c",
                    (ptr[i + c] >= 0x20)&& ( ptr[i + c] < 0x80 ) ? ptr[i + c] : '.' );

            /* check again for 0D0A, to avoid an extra \n if it's at width */
            if(nohex && ( i + c + 2 < size)&& ptr[i + c + 1] == 0x0D && ptr[i + c + 2] == 0x0A ) {
                i +=(c + 3 - width);
                break;
            }
        }

        fputc('\n', stream); /* newline */
    }

    fflush(stream);
}

static int my_trace(CURL *handle, curl_infotype type,
                     char *data, size_t size,
                     void *userp){
    struct data *config =(struct data *)userp;
    const char *text;
   (void)handle; /* prevent compiler warning */

    switch(type){
    case CURLINFO_TEXT:
        fprintf(stderr, "== Info: %s", data);

    default: /* in case a new one is introduced to shock us */
        return 0;

    case CURLINFO_HEADER_OUT:
        text = "=> Send header";
        break;

    case CURLINFO_DATA_OUT:
        text = "=> Send data";
        break;

    case CURLINFO_SSL_DATA_OUT:
        text = "=> Send SSL data";
        break;

    case CURLINFO_HEADER_IN:
        text = "<= Recv header";
        break;

    case CURLINFO_DATA_IN:
        text = "<= Recv data";
        break;

    case CURLINFO_SSL_DATA_IN:
        text = "<= Recv SSL data";
        break;
    }

    dump(text, stderr,( unsigned char *)data, size, config->trace_ascii );
    return 0;
}

//获得一个可用的CURL结构
static CURL* getcurl(){
    struct data config;
    config.trace_ascii = 1; /* enable ascii tracing */
    CURL *curl;
    pthread_mutex_lock(&lockcon);
    struct connect_data *tmp=conhead;
    if(tmp){                                //如果链表中已有一个现有的CURL结构，直接取下来返回
        conhead=conhead->next;
        curl=tmp->handle;
        free(tmp);
        curl_easy_reset(curl);
    }else{                                  //否则新生成一个，设定参数
        curl = curl_easy_init();
    }
    pthread_mutex_unlock(&lockcon);
    curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, my_trace);
    curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &config);
    curl_easy_setopt(curl, CURLOPT_FILETIME, 1);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_FRESH_CONNECT, 0);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2);
    curl_easy_setopt(curl, CURLOPT_CLOSEPOLICY, CURLCLOSEPOLICY_OLDEST);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5);
    curl_easy_setopt(curl, CURLOPT_HEADER, 0);
    curl_easy_setopt(curl, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4); //no ipv6 support for pcs.baidu.com
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 60);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 0);
    return curl;
}


//释放，就是把它加到链表中，
//如果申请内存成功的话并不真的释放
static void releasecurl(CURL *curl){                        
    struct connect_data* tmp=(struct connect_data*)malloc(sizeof(struct connect_data));
    if(tmp==NULL){
        curl_easy_cleanup(curl);
        return;
    }
    tmp->handle=curl;
    pthread_mutex_lock(&lockcon);
    tmp->next=conhead;
    conhead=tmp;
    pthread_mutex_unlock(&lockcon);
}

CURLcode request(Http *r){
//    errorlog("request: %s\n", r->url);
    
    struct curl_httppost *post = NULL;
    struct curl_httppost *last = NULL;
    
    
    curl_easy_setopt(r->curl_handle, CURLOPT_URL, r->url);
    curl_easy_setopt(r->curl_handle, CURLOPT_REFERER, r->url);
    curl_easy_setopt(r->curl_handle, CURLOPT_TIMEOUT, r->timeout);

    char errbuf[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(r->curl_handle, CURLOPT_ERRORBUFFER, errbuf);
    //curl_easy_setopt(r->curl_handle, CURLOPT_FRESH_CONNECT, 1);
    if(r->timeout > 60){
        curl_easy_setopt(r->curl_handle, CURLOPT_LOW_SPEED_LIMIT, 5);
        curl_easy_setopt(r->curl_handle, CURLOPT_LOW_SPEED_TIME, r->timeout/2);
    }
    if(r->range){
        curl_easy_setopt(r->curl_handle, CURLOPT_RANGE, r->range);
    }

    if(r->useragent){
        curl_easy_setopt(r->curl_handle, CURLOPT_USERAGENT, r->useragent);
    }

    if(r->writefunc){
        curl_easy_setopt(r->curl_handle, CURLOPT_WRITEFUNCTION, r->writefunc);
        curl_easy_setopt(r->curl_handle, CURLOPT_WRITEDATA, r->writeprame);
    }

    if(r->readfunc){
        curl_easy_setopt(r->curl_handle, CURLOPT_READFUNCTION, r->readfunc);
        curl_easy_setopt(r->curl_handle, CURLOPT_READDATA, r->readprame);
    }

    switch(r->method){
    case get:
        curl_easy_setopt(r->curl_handle,CURLOPT_HTTPGET,1);
        break;

    case post_formdata:
        curl_formadd(&post, &last,
                      CURLFORM_PTRNAME, "file",
                      CURLFORM_FILENAME, "tmpfile",
                      CURLFORM_CONTENTTYPE, "application/octet-stream",
                      CURLFORM_CONTENTSLENGTH, r->length,
                      CURLFORM_STREAM, r->readprame,
                      CURLFORM_END);
        curl_easy_setopt(r->curl_handle, CURLOPT_HTTPPOST, post);
        break;

    case post_x_www_form_urlencoded:
        curl_easy_setopt(r->curl_handle, CURLOPT_POST, 1);
        curl_easy_setopt(r->curl_handle, CURLOPT_POSTFIELDSIZE, r->length);
        break;

    case head:
        curl_easy_setopt(r->curl_handle, CURLOPT_CUSTOMREQUEST, "HEAD");
        curl_easy_setopt(r->curl_handle, CURLOPT_NOBODY, 1);
        break;
    default:
        errorlog("Unimplise Method!\n");
        return -1;
    }

    CURLcode curl_code = curl_easy_perform(r->curl_handle);
    long http_code = 0;
    curl_easy_getinfo(r->curl_handle, CURLINFO_RESPONSE_CODE, &http_code);
    if(curl_code != CURLE_OK && strlen(errbuf)){
        errorlog("libcurl error: %s\n", errbuf);
    }
    if(curl_code == CURLE_OK && (http_code >= 300 || http_code < 200)){
        return http_code;
    }
    return curl_code;
}


void netinit(){
    while(curl_global_init(CURL_GLOBAL_SSL)!= CURLE_OK) ;     //初始化curl
    init_locks();                                               //设置openssl的锁，让其支持多线程
    conhead=NULL;
    pthread_mutex_init(&lockcon,NULL);
}

Http *Httpinit(const char *url){
    Http *hh = malloc(sizeof(Http));
    assert(hh);
    memset(hh, 0, sizeof(Http));
    hh->curl_handle = getcurl();
    assert(hh->curl_handle);
    hh->url = url;
    hh->method = get;
    hh->timeout = 60;
    return hh;
}

void Httpdestroy(Http *hh){
    releasecurl(hh->curl_handle);
    free(hh);
}
