#include "threadpool.h"
#include <stdlib.h>
#include <unistd.h>
#include <semaphore.h>
#include <assert.h>
#include <unordered_map>
#include <list>

using namespace std;

typedef struct node{
    task_t       taskid;
    taskfunc     task;
    void*        param;
    unsigned int flags;
    sem_t        wait;
    timespec     until;
}tasknode;

typedef struct{
    pthread_cond_t   cond;
    int              done;
    int              waitc;
    void*            val;
}valnode;

typedef struct {
    int              num;
    task_t           curid;     //下一任务分配id
    pthread_t        sched;     //调度线程的线程号
    pthread_t*       id;        //线程池各线程
    sem_t*           wait;      //每个线程等待信号量
    list<tasknode*>  tasks;
    tasknode**       tsk;       //正在执行的任务
}thrdpool;


thrdpool pool;
pthread_mutex_t poollock;              //给任务队列加锁
pthread_mutex_t vallock;                //给结果集合用的锁

sem_t tasksum;                                          //等待调度的任务数
sem_t trdsum;                                           //线程数

unordered_map <task_t, valnode * > valmap;            //结果集合


void *dotask(long t) {                                //执行任务
    void *retval;

    while (1) {
        sem_wait(pool.wait + t);
        pthread_mutex_lock(&poollock);
        tasknode* node = pool.tsk[t];
        pthread_mutex_unlock(&poollock);
        retval = node->task(node->param);

        pthread_mutex_lock(&vallock);
        valnode * val = valmap.at(node->taskid);
        assert(val);
        assert(val->done == 0);
        assert(val->val == nullptr);
        if(val->waitc || (node->flags & NEEDRET)){
            val->done = 1;
            val->val = retval;         //存储结果
            pthread_cond_broadcast(&val->cond); //发信号告诉waittask
        }else{
            valmap.erase(node->taskid);
            pthread_cond_destroy(&val->cond);
            free(val);
        }
        pthread_mutex_unlock(&vallock);

        sem_destroy(&node->wait);
        free(node);

        pthread_mutex_lock(&poollock);
        pool.tsk[t] = 0;
        sem_post(&trdsum);
        pthread_mutex_unlock(&poollock);
    }

    return NULL;
}

//调度线程，按照先进先出的队列来调度
void sched() {
    int i;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += 1e5;
    ts.tv_nsec = 0;
    while (1) {
        sem_timedwait(&tasksum, &ts);             //等待addtask的信号
        sem_wait(&trdsum);                        //等待一个空闲进程

        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        ts.tv_sec = now.tv_sec + 1e5;

        pthread_mutex_lock(&poollock);
        for(i = 0; i < pool.num; ++i) {
            if (pool.tsk[i] == 0)break;        //找到空闲进程号
        }
        tasknode* task = nullptr;
        for(auto i = pool.tasks.begin(); i != pool.tasks.end();){
            auto tv_sec = (*i)->until.tv_sec;
            if(task == nullptr && tv_sec <= now.tv_sec){
                task = *i;
                i = pool.tasks.erase(i);
                continue;
            }
            if(tv_sec < ts.tv_sec){
                ts.tv_sec = tv_sec;
            }
            i++;
        }
        if(task){
            pool.tsk[i] = task;              //分配任务
        }
        pthread_mutex_unlock(&poollock);
        if(task){
            sem_post(&task->wait);
            sem_post(pool.wait + i);
        }else{
            sem_post(&trdsum);
        }
    }
}


void creatpool(int threadnum) {
    pool.num = threadnum;
    pool.curid = 1;
    pool.id = (pthread_t *)malloc(pool.num * sizeof(pthread_t));
    pool.wait = (sem_t *)malloc(pool.num * sizeof(sem_t));
    pool.tsk = (tasknode **)malloc(pool.num * sizeof(tasknode *));

    sem_init(&tasksum, 0 , 0);
    sem_init(&trdsum, 0 , threadnum);
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setstacksize(&attr, 20*1024*1024);               //设置20M的栈
    pthread_create(&pool.sched, &attr , (taskfunc)sched, NULL);   //创建调度线程
    pthread_mutex_init(&poollock, NULL);
    pthread_mutex_init(&vallock, NULL);
    for (long i = 0; i < pool.num; ++i) {
        sem_init(pool.wait + i, 0, 0);
        pool.tsk[i] = nullptr;
        pthread_create(pool.id + i, &attr, (taskfunc)dotask, (void *)i);
    }
    pthread_attr_destroy(&attr);
}


task_t addtask(taskfunc task, void *param , uint flags, unsigned int delaySec) {
    tasknode *t = (tasknode *)malloc(sizeof(tasknode));   //生成一个任务块
    t->param = param;
    t->task = task;
    t->flags = flags;
    clock_gettime(CLOCK_REALTIME, &t->until);
    t->until.tv_sec += delaySec;
    t->until.tv_nsec = 0;
    sem_init(&t->wait, 0, 0);

    valnode *val = (valnode *)malloc(sizeof(valnode));
    val->done = 0;
    val->waitc = 0;
    val->val = nullptr;
    val->cond= PTHREAD_COND_INITIALIZER;

    pthread_mutex_lock(&poollock);
    t->taskid = pool.curid++;
    pool.tasks.push_back(t);                              //加入任务队列尾部
    pthread_mutex_lock(&vallock);
    valmap[t->taskid] = val;
    assert(val);
    pthread_mutex_unlock(&vallock);
    
    pthread_mutex_unlock(&poollock);
    sem_post(&tasksum);                                       //发信号给调度线程
    if(flags & WAIT){
        sem_wait(&t->wait);
    }
    return t->taskid;
}


//多线程同时查询，只保证最先返回的能得到结果，其他有可能返回NULL
void *waittask(task_t id) {
    if(id == 0){
recheck:
        pthread_mutex_lock(&poollock);
        if(!pool.tasks.empty()){
            pthread_mutex_unlock(&poollock);
            sleep(5);
            goto recheck;
        }

        for(auto i = 0; i < pool.num; ++i) {
            if (pool.tsk[i]){
                pthread_mutex_unlock(&poollock);
                sleep(5);
                goto recheck;
            }
        }
        pthread_mutex_unlock(&poollock);
        return nullptr;
    }
    void *retval = NULL;
    pthread_mutex_lock(&vallock);
    int count = valmap.count(id);

    if (count == 0) {                              //没有该任务或者已经取回结果，返回NULL
        pthread_mutex_unlock(&vallock);
        return NULL;
    }
    
    valnode *val = valmap.at(id);
    val->waitc++;
    while(val->done == 0){
        assert(val->val == nullptr);
        pthread_cond_wait(&val->cond, &vallock);   //等待任务结束
    }

    retval=val->val;
    val->waitc -- ;
    if(val->waitc==0){                             //没有其他线程在等待结果，做清理操作
        pthread_cond_destroy(&val->cond); 
        free(val);
        valmap.erase(id); 
    }
    pthread_mutex_unlock(&vallock);
    return retval;
}


int taskisdoing(task_t id) {
    pthread_mutex_lock(&vallock);
    auto t = valmap.count(id);                     //没有该任务或者已经取回结果，返回0
    pthread_mutex_unlock(&vallock);
    return t;
}
