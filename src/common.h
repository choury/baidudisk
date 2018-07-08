#include <linux/limits.h>

#ifndef COMMON_H__
#define COMMON_H__

#define BLOCKLEN       (uint64_t)0x100000          //1M,缓存分块大小 必须为4K的倍数
#define PATHLEN        1024
#define THREADS        50

#define API_AK       "iN1yzFR9Sos27UWGEpjvKNVs"
#define METANAME     "/meta.json"

extern char COFPATH[];
#endif
