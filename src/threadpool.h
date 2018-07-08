#include <pthread.h>
#include <semaphore.h>

#ifndef __THREADPOOL_H__
#define __THREADPOOL_H__


//TODO 没有销毁线程池的操作……

#ifdef  __cplusplus
extern "C" {
#endif

typedef unsigned long int task_t;               //任务id
typedef void *(*taskfunc)(void *);

void creatpool(int threadnum);                          //创建线程池，参数是线程数

//增加一个任务，执行task函数，参数为param

#define NEEDRET     1
#define WAIT        2
task_t addtask(taskfunc task, void* param, uint flags, unsigned int delaySec);
void* waittask(task_t id);                              //等待并取回结果，必须对每个needretval=1的任务执行，不然会导致类似"僵尸进程"的东西
int taskisdoing(task_t id);         //这是一个非阻塞接口，用来查询某任务是否在队列或者被执行

#ifdef  __cplusplus
}
#endif  /* end of __cplusplus */

#endif
