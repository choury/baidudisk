#include <pthread.h>
#include <semaphore.h>

#ifndef __THREADPOOL_H__
#define __THREADPOOL_H__

#define THREADS 15

//TODO 没有销毁线程池的操作……

#ifdef  __cplusplus
extern "C" {
#endif

typedef unsigned long int task_t;               //任务id
typedef void *(*taskfunc)(void *);
typedef struct node{
    task_t taskid;
    taskfunc task;
    void *param;
    unsigned int flags;
    pthread_mutex_t lock;
    struct node *next;
}tasknode;

typedef struct{
    sem_t  wait;
    int    done;
    int    waitc;
    void*  val;
}valnode;

typedef struct {
    int num;
    task_t curid;               //下一任务分配id
    pthread_t sched;            //调度线程的线程号
    pthread_t *id;              //线程池各线程
    pthread_mutex_t *lock;      //每个线程调度锁
    tasknode *taskhead;         //任务队列头指针
    tasknode *tasktail;         //任务队列尾指针
    task_t *taskid;             //各线程正在执行的任务id,如为0则表示空闲
    tasknode **tsk;             //正在执行的任务
}thrdpool;

void creatpool(int threadnum);                          //创建线程池，参数是线程数

//增加一个任务，执行task函数，参数为param

#define NEEDRET     1
#define WAIT        2
task_t addtask( taskfunc task, void *param ,uint flags);
void* waittask(task_t id);                              //等待并取回结果，必须对每个needretval=1的任务执行，不然会导致类似"僵尸进程"的东西
int taskisdoing(task_t id);         //这是一个非阻塞接口，用来查询某任务是否在队列或者被执行

#ifdef  __cplusplus
}
#endif  /* end of __cplusplus */

#endif
