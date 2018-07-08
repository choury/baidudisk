#ifndef LOCKER_H__
#define LOCKER_H__

#include <errno.h>
#include <assert.h>
#include <pthread.h>

#include <set>

class locker{
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_t writer = 0;
    std::set<pthread_t> reader;
public:
    virtual ~locker(){
        pthread_cond_destroy(&cond);
        pthread_mutex_destroy(&lock);
    }
    virtual int rlock(){
        pthread_t self = pthread_self();
        pthread_mutex_lock(&lock);
        if(writer == self){
            pthread_mutex_unlock(&lock);
            return EDEADLK;
        }
        while(writer){
            pthread_cond_wait(&cond, &lock);
        }
        if(reader.count(self)){
            pthread_mutex_unlock(&lock);
            return EDEADLK;
        }else{
            reader.insert(self);
            pthread_mutex_unlock(&lock);
            return 0;
        }
    }
    virtual int tryrlock(){
        pthread_t self = pthread_self();
        pthread_mutex_lock(&lock);
        if(writer == self){
            pthread_mutex_unlock(&lock);
            return EDEADLK;
        }
        if(writer){
            pthread_mutex_unlock(&lock);
            return EAGAIN;
        }
        if(reader.count(self)){
            pthread_mutex_unlock(&lock);
            return EDEADLK;
        }else{
            reader.insert(self);
            pthread_mutex_unlock(&lock);
            return 0;
        }
    }
    virtual int wlock(){
        pthread_t self = pthread_self();
        pthread_mutex_lock(&lock);
        if(writer == self){
            pthread_mutex_unlock(&lock);
            return EDEADLK;
        }
        while(true){
            if(!writer && reader.empty()){
                break;
            }
            if(!writer && reader.size() == 1 && reader.count(self)){
                break;
            }
            pthread_cond_wait(&cond, &lock);
        }
        writer = self;
        pthread_mutex_unlock(&lock);
        return 0;
    }
    virtual int upgrade(){
        pthread_t self = pthread_self();
        pthread_mutex_lock(&lock);
        if(writer == self){
            pthread_mutex_lock(&lock);
            return EEXIST;
        }
        assert(reader.count(self));
        reader.erase(self);
        while(true){
            if(!writer && reader.empty()){
                break;
            }
            pthread_cond_wait(&cond, &lock);
        }
        writer = self;
        pthread_mutex_unlock(&lock);
        return 0;
    }
    virtual void unrlock(){
        pthread_mutex_lock(&lock);
        assert(reader.count(pthread_self()));
        reader.erase(pthread_self());
        pthread_cond_signal(&cond);
        pthread_mutex_unlock(&lock);
    }
    virtual void unwlock(){
        pthread_mutex_lock(&lock);
        assert(writer == pthread_self());
        writer = 0;
        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&lock);
    }
};

class auto_locker{
    bool locked = false;
    pthread_mutex_t* l;
public:
    auto_locker(const auto_locker&) = delete;
    auto_locker(pthread_mutex_t* l):l(l){
        int ret = pthread_mutex_lock(l);
        if(ret == EDEADLK){
            return;
        }
        assert(ret == 0);
        locked = true;
    }
    ~auto_locker(){
        if(!locked){
            return;
        }
        pthread_mutex_unlock(l);
    }
};

class auto_rlocker{
    bool locked = false;
    bool upgraded = false;
    locker* l;
public:
    auto_rlocker(const auto_rlocker&) = delete;
    auto_rlocker(locker* l):l(l){
        int ret = l->rlock();
        if(ret == EDEADLK){
            return;
        }
        assert(ret == 0);
        locked = true;
    }
    int upgrade(){
        assert(locked);
        int ret = l->upgrade();
        assert(ret == 0);
        upgraded = true;
        return ret;
    }
    void unlock(){
        if(!locked){
            return;
        }
        if(upgraded){
            l->unwlock();
        }else{
            l->unrlock();
        }
        locked = false;
        upgraded = false;
    }
    ~auto_rlocker(){
        if(!locked){
            return;
        }
        if(upgraded){
            l->unwlock();
        }else{
            l->unrlock();
        }
    }
};

class auto_wlocker{
    bool locked = false;
    locker* l;
public:
    auto_wlocker(const auto_wlocker&) = delete;
    auto_wlocker(locker* l):l(l){
        int ret = l->wlock();
        if(ret == EDEADLK){
            return;
        }
        assert(ret == 0);
        locked = true;
    }
    void unlock(){
        if(!locked){
            return;
        }
        l->unwlock();
        locked = false;
    }
    ~auto_wlocker(){
        if(locked){
            l->unwlock();
        }
    }
};

#define auto_lock(x)  auto_locker __l(x)
#define auto_rlock(x) auto_rlocker __r(x)
#define auto_wlock(x) auto_wlocker __w(x)

#endif
