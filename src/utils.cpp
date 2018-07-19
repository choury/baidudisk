#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>

#include "utils.h"

using std::string;

char COFPATH[4096];

void setCOFPATH(){
    sprintf(COFPATH, "%s/.baidudisk", getenv("HOME"));
    mkdir(COFPATH, 0700);
}

static int hex2num(char c) {
    if (c>='0' && c<='9') return c - '0';
    if (c>='a' && c<='z') return c - 'a' + 10;//这里+10的原因是:比如16进制的a值为10
    if (c>='A' && c<='Z') return c - 'A' + 10;

    fprintf(stderr, "unexpected char: %c", c);
    return '0';
}

string URLEncode(const char* s) {
    int strSize=strlen(s);
    const unsigned char *str = (const unsigned char*)s;

    if ((str==NULL) || (strSize==0) ) {
        return NULL;
    }
    string result;
    for (int i=0; i<strSize; ++i) {
        unsigned char ch = str[i];
        if (((ch>='A') && (ch<='Z')) ||
            ((ch>='a') && (ch<='z')) ||
            ((ch>='0') && (ch<='9'))) {
            result += ch;
        } else if (ch == ' ') {
            result += '+';
        } else if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
            result += ch;
        } else {
            char tmp[4];
            sprintf(tmp, "%%%02X", ch);
            result += tmp;
        }
    }

    return result;
}


string URLDecode(const char* str) {
    int strSize = strlen(str);
    if ((str==NULL) || (strSize<=0) ) {
        return 0;
    }

    string result;
    for (int i=0; i<strSize; ++i) {
        char ch = str[i];
        switch (ch) {
        case '+':
            result += ' ';
            break;
        case '%':
            if (i+2<strSize) {
                char ch1 = hex2num(str[i+1]);//高4位
                char ch2 = hex2num(str[i+2]);//低4位
                if ((ch1!='0') && (ch2!='0'))
                    result += (char)((ch1<<4) | ch2);
                i += 2;
                break;
            } else {
                break;
            }
        default:
            result += ch;
            break;
        }
    }
    return result;
}

static const char *base64_endigs="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

string Base64Encode(const char *s, size_t len){
    string dst;
    size_t i=0;
    len = len?len:strlen(s);
    const unsigned char *src = (const unsigned char*)s;
    for(;i+2<len;i+=3){
        dst += base64_endigs[src[i]>>2];
        dst += base64_endigs[((src[i]<<4) & 0x30) | src[i+1]>>4];
        dst += base64_endigs[((src[i+1]<<2) & 0x3c) | src[i+2]>>6];
        dst += base64_endigs[src[i+2] & 0x3f];
    }
    if(i == len-1){
        dst += base64_endigs[src[i]>>2];
        dst += base64_endigs[(src[i]<<4) & 0x30];
        dst += "==";
    }else if(i == len-2){
        dst += base64_endigs[src[i]>>2];
        dst += base64_endigs[((src[i]<<4) & 0x30) | src[i+1]>>4];
        dst += base64_endigs[(src[i+1]<<2) & 0x3c];
        dst += '=';
    }
    return dst;
}

static const char base64_dedigs[128] = 
{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
 0,0,0,0,0,0,0,0,0,0,0,0,0,62,0,0,
 52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
 0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
 15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,63,
 0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
 41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0};

string Base64Decode(const char *src){
    size_t len = strlen(src);
    string result;
    for(size_t i=0;i<len; i+= 4){
        char ch1 = (base64_dedigs[(int)src[i]]<<2) | (base64_dedigs[(int)src[i+1]] >>4);
        char ch2 = (base64_dedigs[(int)src[i+1]]<<4) | (base64_dedigs[(int)src[i+2]] >>2);
        char ch3 = (base64_dedigs[(int)src[i+2]]<<6) | base64_dedigs[(int)src[i+3]];
        result += ch1;
        if(ch2)
            result += ch2;
        if(ch3)
            result += ch3;
    }
    return result;
}

void xorcode(void* buf, size_t offset, size_t len, const char* key){
    unsigned char* buff= (unsigned char*)buf;
    size_t klen = strlen(key);
    size_t koffset = offset%klen;
    string key_tune = string(key+koffset)+string(key).substr(0, koffset);
    for(size_t i=0;i<len;i+=klen){
        for(size_t j=0;j<klen && i+j<len;j++){
            buff[i+j] ^= key_tune[j];
        }
    }
}

string basename(const string& path) {
    size_t pos = path.find_last_of("/");
    if(pos == string::npos) {
        return path;
    }
    if(path.length() == 1){
        return path;
    }
    if(pos == path.length() -1 ) {
        string path_truncate = path.substr(0, path.length()-1);
        return basename(path_truncate);
    }
    return path.substr(pos+1, path.length());
}

string dirname(const string& path) {
    size_t pos = path.find_last_of("/");
    if(pos == string::npos) {
        return ".";
    }
    if(path.length() == 1){
        return path;
    }
    if(pos == path.length() -1 ) {
        string path_truncate = path.substr(0, path.length()-1);
        return dirname(path_truncate);
    }
    return path.substr(0, pos+1);
}


bool endwith(const string& s1, const string& s2){
    auto l1 = s1.length();
    auto l2 = s2.length();
    if(l1 < l2)
        return 0;
    return !memcmp(s1.data()+l1-l2, s2.data(), l2);
}

bool startwith(const string& s1, const string& s2){
    auto l1 = s1.length();
    auto l2 = s2.length();
    if(l1 < l2)
        return 0;
    return !memcmp(s1.data(), s2.data(), l2);
}

string encodepath(const string& path){
    if(dirname(path) == "."){
        return Base64Encode(basename(path).c_str()) + ".def";
    }else{
        return dirname(path)+Base64Encode(basename(path).c_str()) + ".def";
    }
}

string decodepath(const string& path){
    assert(endwith(path, ".def"));
    string base = basename(path);
    if(dirname(path) == "."){
        return Base64Decode(base.substr(0, base.length()-4).c_str());
    }else{
        return dirname(path)+Base64Decode(base.substr(0, base.length()-4).c_str());
    }
}


buffstruct::buffstruct(char* buf, size_t len):buf(buf),len(len) {
    offset = 0;
    if(this->buf == nullptr){
        this->buf = (char*)calloc(1024, 1);
        len = 1024;
    }else{
        assert(len);
    }
}

buffstruct::buffstruct(const char* buf, size_t len):buf((char *)buf), len(len) {
    const_buff = true;
}


void buffstruct::expand(size_t size){
    if(const_buff){
        assert(0);
        return;
    }
    if(offset + size >= len){
        len = ((offset + size)&0xfffffffffc00)+1024;
        buf = (char*)realloc(buf, len);
        memset(buf + offset, 0, len - offset);
    }
}

buffstruct::~buffstruct() {
    if(!const_buff && buf){
        free(buf);
    }
}



//顾名思义，将服务器传回的数据写到buff中
size_t savetobuff(void *buffer, size_t size, size_t nmemb, void *user_p)
{
    buffstruct *bs = (buffstruct *) user_p;
    size_t len = size * nmemb;
    bs->expand(len);
    memcpy(bs->buf + bs->offset, buffer, len);
    bs->offset += len;
    return len;
}

//你猜
size_t readfrombuff(void *buffer, size_t size, size_t nmemb, void *user_p)
{
    buffstruct *bs = (buffstruct *) user_p;
    size_t len = std::min(size * nmemb, (bs->len) - (size_t)bs->offset);
    memcpy(buffer, bs->buf + bs->offset, len);
    bs->offset += len;
    return len;
}

