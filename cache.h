#ifndef __CACHE_H__
#define __CACHE_H__

#include "threadpool.h"
#include <time.h>

#ifdef  __cplusplus
extern "C" {
#endif

    
#define RBS            (uint64_t)0x200000         //1M,读缓存分块大小
#define LWBS           (uint64_t)0x800000         //8M,前一半分块大小
#define HWBS           (uint64_t)0x2000000        //32M,后一半分块大小
#define RBC            (uint64_t)10240            //读缓存个数
#define WBC            (uint64_t)1024             //写缓存分块个数，百度定的，最大1024
#define MAXCACHE       10
    
#define PATHLEN        1024    

                    

typedef struct{
    task_t taskid[RBC];
    unsigned int mask[RBC/32+1];                //为1代表已经从服务器成功读取
}rfcache;

typedef struct{
    char md5[WBC][35];
    task_t taskid[WBC];
    
//每一个block有4位标志位：bit0(D):是否为脏块，bit1(T):是否正在同步,bit2(R):同步时是否被写,bit3:保留
    unsigned int flags[WBC/8+1];
#define SETD(flags,b)  (flags[(b)>>3] |= (1<<(((b)%8)<<2)))
#define CLRD(flags,b)  (flags[(b)>>3] &= ~(1<<(((b)%8)<<2)))
#define GETD(flags,b)  (flags[(b)>>3] & (1<<(((b)%8)<<2)))
#define SETT(flags,b)  (flags[(b)>>3] |= (1<<((((b)%8)<<2)+1)))
#define CLRT(flags,b)  (flags[(b)>>3] &= ~(1<<((((b)%8)<<2)+1)))
#define GETT(flags,b)  (flags[(b)>>3] & (1<<((((b)%8)<<2)+1)))
#define SETR(flags,b)  (flags[(b)>>3] |= (1<<((((b)%8)<<2)+2)))
#define CLRR(flags,b)  (flags[(b)>>3] &= ~(1<<((((b)%8)<<2)+2)))
#define GETR(flags,b)  (flags[(b)>>3] & (1<<((((b)%8)<<2)+2)))

}wfcache;


typedef struct{
    enum{forread,forwrite}type;
    char path[PATHLEN];
    pthread_mutex_t lock;
    int file;
    union{
        rfcache r;
        wfcache w;
    }cache;
    size_t lengh;
    size_t count;
    time_t rlstime;
    
#define SYNCED         1                        //是否已同步
#define TRANSF         2                        //是否正在同步
#define DELETE         4                        //是否被标记删除
#define REOPEN         8                        //是否同步时被重新打开过
#define ONDELE        16                        //正在被删除
    volatile unsigned char flags;
}filedec;


typedef void (*eachfunc)(filedec *f);

size_t GetWriteBlkStartPoint(size_t b);
size_t GetWriteBlkEndPoint(size_t b);
size_t GetWriteBlkNo(size_t p);
size_t GetWriteBlkEndPointFromP(size_t p);
#define GetWriteBlkSize(b)  ((b)<WBC/2?LWBS:HWBS)

void initcache();
filedec * initfcache(const char *path);
int freefcache(filedec *f);
void addfcache(filedec *f);
void addscache(const char* path,struct stat st);
filedec *getfcache(const char *path);
struct stat *getscache(const char *path);
void rmfcache(const char *path);
void rmscache(const char *path);
void clearscache();
void renamecache(const char *oldname,const char *newname);
void eachfcache(eachfunc func);
void filldir(const char *path,void *buf,fuse_fill_dir_t filler);
void fcachesync(filedec *f);

#ifdef  __cplusplus
}
#endif

#endif
