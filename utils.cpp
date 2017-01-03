#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

using std::string;

int hex2num(char c)
{
    if (c>='0' && c<='9') return c - '0';
    if (c>='a' && c<='z') return c - 'a' + 10;//这里+10的原因是:比如16进制的a值为10
    if (c>='A' && c<='Z') return c - 'A' + 10;

    printf("unexpected char: %c", c);
    return '0';
}

string URLEncode(const char* str) {
    int strSize=strlen(str);

    if ((str==NULL) || (strSize==0) ) {
        return NULL;
    }
    string result;
    for (int i=0; i<strSize; ++i) {
        char ch = str[i];
        if (((ch>='A') && (ch<'Z')) ||
            ((ch>='a') && (ch<'z')) ||
            ((ch>='0') && (ch<'9'))) {
            result += ch;
        } else if (ch == ' ') {
            result += '+';
        } else if (ch == '.' || ch == '-' || ch == '_' || ch == '*') {
            result += ch;
        } else {
            char tmp[4];
            sprintf(tmp, "%%%02X", (unsigned char)ch);
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

string Base64Encode(const char *src, size_t len){
    string dst;
    size_t i=0;
    len = len?len:strlen(src);
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
 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,63,
 0,0,0,0,0,0,0,0,0,0,0,0,0,62,0,0,
 52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
 0,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,
 15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,
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


