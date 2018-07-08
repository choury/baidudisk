#include "locker.h"
#include <iostream>
#include <thread>

#include <unistd.h>

using namespace std;

void lock_read(int i, locker* l){
    l->rlock();
    cout<<"rlock: "<<i<<endl;
    sleep(3);
    l->unrlock();
    cout<<"rlock unlocked: "<<i<<endl;
}

void lock_write(int i, locker* l){
    l->wlock();
    cout<<"wrlock: "<<i<<endl;
    sleep(3);
    l->unwlock();
    cout<<"wlock unlocked: "<<i<<endl;
}


void test1(){
    locker l;
    cout<<"rlock once in test1: "<<l.rlock()<<endl;
    cout<<"rlock twice in test1: "<<l.rlock()<<endl;
    cout<<"wlock once in test1: "<<l.wlock()<<endl;
    cout<<"wlock twice in test1: "<<l.wlock()<<endl;
    l.unrlock();
    l.unwlock();
    cout<<"---------------"<<endl;
    thread  rt1(lock_read, 1, &l);
    rt1.detach();
    thread  rt2(lock_read, 2, &l);
    rt2.detach();
    thread  wt1(lock_write, 1, &l);
    thread  wt2(lock_write, 2, &l);
    wt1.join();
    wt2.join();
}

void lock_upgrade(int i, locker* l){
    l->rlock();
    cout<<"rlock in upgrade: "<<i<<endl;
    sleep(3);
    l->upgrade();
    cout<<"upgrade in upgrade: "<<i<<endl;
    l->unwlock();
    cout<<"wlock unlocked in upgrade: "<<i<<endl;
}

void test2(){
    locker l;
    cout<<"rlock in test2: "<<l.rlock()<<endl;
    thread t1(lock_read, 1, &l);
    thread t2(lock_write, 1, &l);
    t1.detach();
    cout<<"upgrade in test2: "<<l.upgrade()<<endl;
    sleep(3);
    cout<<"unwlock in test2"<<endl;
    l.unwlock();
    t2.join();

    cout<<"---------------"<<endl;
    thread u1(lock_upgrade, 1, &l);
    thread u2(lock_upgrade, 2, &l);
    u1.join();
    u2.join();
}


int main(){
    test1();
    cout<<"================"<<endl;
    test2();
}
