#ifndef __CWMP_THREAD_POOL_H__
#define __CWMP_THREAD_POOL_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"
#include "queue.h"
#include <pthread.h>

typedef void (*thread_pool_worker_func)(void *arg);

typedef struct thread_worker_st{
    thread_pool_worker_func func;
    void *arg;
}thread_worker_t;

typedef struct thread_pool_st{
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    queue_head_t waiting;
    queue_head_t idleing;
    uint32 thdnum;
    BOOL destroying;
    pthread_t thdid[0];
}thread_pool_t;

thread_pool_t * thread_pool_create(uint32 maxnum);
void thread_pool_destroy(thread_pool_t *pool);
int32 thread_pool_worker_add(thread_pool_t *pool,
                             thread_pool_worker_func func,
                             void *arg);


#ifdef  __cplusplus
}
#endif

#endif /*__CWMP_THREAD_POOL_H__*/

