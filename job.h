#ifndef JOB_H__
#define JOB_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*job_func)(void *);
void add_job(job_func func,  void *arg, uint32_t interval);
void del_job(job_func func, void *arg);
uint32_t do_job();

#ifdef  __cplusplus
}
#endif

#endif
