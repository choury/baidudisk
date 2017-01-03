#ifndef __URL_CODE__
#include <string>

std::string URLEncode(const char* str);
std::string URLDecode(const char* str);
std::string Base64Encode(const char *src, size_t len=0);
std::string Base64Decode(const char *src);
void xorcode(void* buf, size_t offset, size_t len, const char* key);

#endif
