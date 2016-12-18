#ifndef __CACHE_H__
#define __CACHE_H__

#include "threadpool.h"
#include <time.h>

#ifdef  __cplusplus
extern "C" {
#endif

    
#define RBS            (uint64_t)0x100000         //1M,读缓存分块大小
#define LWBS           (uint64_t)0x800000         //8M,前一半分块大小
#define HWBS           (uint64_t)0x2000000        //32M,后一半分块大小
#define RBC            (uint64_t)10240            //读缓存个数
#define WBC            (uint64_t)1024             //写缓存分块个数，百度定的，最大1024
#define MAXCACHE       50
    
#define PATHLEN        1024    

                    

typedef struct{
    task_t taskid[RBC];
    unsigned int mask[RBC/32+1];                //为1代表已经从服务器成功读取
}rfcache;

typedef struct{
    char md5[WBC][35];
    task_t taskid[WBC];
    
//每一个block有4位标志位：bit0(D):是否为脏块,bit1(R):同步时是否被写,bit2(Z):全0块（空洞），bit3:保留
    unsigned int flags[WBC/8+1];
//设置D位会同时清除Z位
#define SETD(flags,b)  do{\
                           (flags[(b)>>3] |= (1<<(((b)%8)<<2)));\
                           (flags[(b)>>3] &= ~(1<<((((b)%8)<<2)+2)));\
                       }while(0)
#define CLRD(flags,b)  (flags[(b)>>3] &= ~(1<<(((b)%8)<<2)))
#define GETD(flags,b)  (flags[(b)>>3] & (1<<(((b)%8)<<2)))
#define SETR(flags,b)  (flags[(b)>>3] |= (1<<((((b)%8)<<2)+1)))
#define CLRR(flags,b)  (flags[(b)>>3] &= ~(1<<((((b)%8)<<2)+1)))
#define GETR(flags,b)  (flags[(b)>>3] & (1<<((((b)%8)<<2)+2)))
#define SETZ(flags,b)  (flags[(b)>>3] |= (1<<((((b)%8)<<2)+2)))
#define CLRZ(flags,b)  (flags[(b)>>3] &= ~(1<<((((b)%8)<<2)+2)))
#define GETZ(flags,b)  (flags[(b)>>3] & (1<<((((b)%8)<<2)+2)))
#define CLRA(flags,b)  (flags[(b)>>3] &= ~(0xf<<(((b)%8)<<2)))
}wfcache;


typedef struct{
    enum{forread,forwrite}type;
    char path[PATHLEN];
    pthread_mutex_t lock;
    int fd;
    union{
        rfcache r;
        wfcache w;
    }cache;
    size_t lengh;
    size_t count;
    time_t ctime;
    time_t mtime;
    
#define SYNCED         1                        //是否已同步
#define TRANSF         2                        //是否正在同步
#define DELETE         4                        //是否被标记删除
#define RELEASE        8                        //是否被标记释放
#define REOPEN        16                        //是否同步时被重新打开过
#define ONDELE        32                        //正在被删除或者释放
#define ENCRYPT       64                        //加密文件
    volatile unsigned char flags;
}filedec;


typedef void (*eachfunc)(filedec *f);

size_t GetWriteBlkStartPoint(size_t b);
size_t GetWriteBlkEndPoint(size_t b);
size_t GetWriteBlkNo(size_t p);
size_t GetWriteBlkEndPointFromP(size_t p);
#define GetWriteBlkSize(b)  ((b)<WBC/2?LWBS:HWBS)

void initcache();
void renamecache(const char *oldname,const char *newname);
void fcachesync(filedec *f);


filedec * newfcache(const char *path);
int freefcache(filedec *f);
void addfcache(filedec *f);
filedec *getfcache(const char *path);
void eachfcache(eachfunc func);
void filldir(const char *path,void *buf,fuse_fill_dir_t filler);

void addscache(const char* path, const struct stat* st);
struct stat getscache(const char *path);
void rmscache(const char *path);


#ifdef  __cplusplus
}
#endif

#endif
