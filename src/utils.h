#ifndef UTILS_H__
#define UTILS_H__

#include <string>

class buffstruct {
    bool const_buff = false;
public:
    size_t offset = 0;
    char *buf;
    size_t len;
    buffstruct(char* buf = nullptr, size_t len = 0);
    buffstruct(const char* buf, size_t len);
    void expand(size_t size);
    ~buffstruct();
};


std::string URLEncode(const char* str);
std::string URLDecode(const char* str);
std::string Base64Encode(const char *src, size_t len=0);
std::string Base64Decode(const char *src);
void xorcode(void* buf, size_t offset, size_t len, const char* key);

std::string dirname(const std::string& path);
std::string basename(const std::string& path);
std::string encodepath(const std::string& path);
std::string decodepath(const std::string& path);
bool endwith(const std::string& s1, const std::string& s2);

size_t savetobuff(void *buffer, size_t size, size_t nmemb, void *user_p);
size_t readfrombuff(void *buffer, size_t size, size_t nmemb, void *user_p);
#endif
