#ifndef BAIDUAPI_H__
#define BAIDUAPI_H__
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <map>
#include <set>
#include <string>

#include "common.h"
#include "utils.h"

/*
 * 各api定义参阅http://developer.baidu.com/wiki/index.php?title=docs/pcs/rest/file_data_apis_list
 * 
 */

void baiduapi_prepare();
int baiduapi_statfs(const char *path, struct statvfs *sf);
int baiduapi_download(const char* path, size_t startp, size_t len, buffstruct& bs);
int baiduapi_upload(const char* path, const char* input, size_t len, bool overwrite, char outpath[PATHLEN]);
int baiduapi_list(const char* path, size_t limit, std::map<std::string, struct stat>& stmap);
int baiduapi_getattr(const char *path, struct stat *st);
int baiduapi_mkdir(const char *path, struct stat* st);
int baiduapi_delete(const char *path);
int baiduapi_batchdelete(std::set<std::string> flist);
int baiduapi_rename(const char *oldname, const char *newname);

#define HANDLE_EAGAIN(x) ({       \
  __typeof__(x) _result;          \
  do                              \
  {                               \
    _result = (x);                \
  }while (_result != 0            \
  && (errno == EAGAIN ||          \
      errno == ETIMEDOUT ||       \
      errno == EBUSY));           \
  _result;                        \
})

#endif
