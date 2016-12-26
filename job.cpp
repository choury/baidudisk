#include "job.h"
#include <map>
#include <vector>
#include <mutex>
#include <time.h>

std::mutex mtx;

struct job_n{
    void (* func)(void *);
    void *arg;
};

struct job_v{
    uint32_t interval;
    time_t last_done;
};


class job_n_cmp{
public:
    bool operator()(const struct job_n& a, const struct job_n& b) const{
        if(a.func == b.func){
            return a.arg < b.arg;
        }else{
            return a.func < b.func;
        }
    }
};

std::map<job_n, job_v, job_n_cmp> callfunc_map;

void add_job(job_func func, void *arg, uint32_t interval){
    mtx.lock();
    callfunc_map[job_n{func, arg}] = job_v{interval, time(0)};
    mtx.unlock();
}

void del_job(job_func func, void *arg){
    mtx.lock();
    callfunc_map.erase(job_n{func, arg});
    mtx.unlock();
}

uint32_t do_job(){
    time_t now = time(0);
    uint32_t min_interval = 0xffffffff;
    std::vector<job_n> job_set;
    mtx.lock();
    for(auto i=callfunc_map.begin(); i!= callfunc_map.end(); i++){
        uint32_t diff = now - i->second.last_done;
        if(diff >= i->second.interval){
            i->second.last_done = now;
            job_set.push_back(i->first);
        }
        uint32_t left = i->second.interval + i->second.last_done - now;
        if(left < min_interval){
            min_interval = left;
        }
    }
    mtx.unlock();
    for(auto i:job_set){
        i.func(i.arg);
    }
    return min_interval;
}
