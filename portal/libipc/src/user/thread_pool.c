#include <stdio.h>  
#include <stdlib.h>  
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <strings.h>
#include "type.h"
#include "debug.h"
#include "thread_pool.h"

static void *thread_pool_func(void *arg)
{
    thread_pool_t *pool = (thread_pool_t *)arg;
    queue_item_t *item = NULL;
    thread_worker_t *worker = NULL;
    ASSERT(NULL != pool);
    while (1)
    {
        pthread_mutex_lock(&(pool->mutex));
        if (TRUE == pool->destroying)
        {
            pthread_mutex_unlock(&(pool->mutex));
            break;
        }
        while (TRUE == queue_empty(&(pool->waiting)))
        {
            pthread_cond_wait(&(pool->cond), &(pool->mutex));
            /*maybe awakened by pthread_cond_broadcast for thread pool destroy*/
            if (TRUE == pool->destroying)
            {
                pthread_mutex_unlock(&(pool->mutex));
                pthread_exit(NULL);
            }
        }
        /*dequeue an item from waiting queue*/
        ASSERT(FALSE == queue_empty(&(pool->waiting)));
        item = queue_dequeue(&(pool->waiting));
        ASSERT(NULL != item);
        pthread_mutex_unlock(&(pool->mutex));
        /*TODO: execute worker function*/
        worker = (thread_worker_t *)(item->arg);
        ASSERT(NULL != worker);
        ASSERT(NULL != worker->func);
        worker->func(worker->arg);
        /*add item to the pool's idleing queue, it will be reused next time*/
        pthread_mutex_lock(&(pool->mutex));
        queue_enqueue(&(pool->idleing), item);
        pthread_mutex_unlock(&(pool->mutex));
    }
    pthread_exit(NULL);
}

thread_pool_t *thread_pool_create(uint32 maxnum)
{
    int32 i;
    thread_pool_t *pool = NULL;
    int32 size = sizeof(*pool) + (sizeof(pool->thdid[0]) * maxnum);
    if (maxnum <= 0)
        return NULL;
    pool = malloc(size);
    bzero(pool, size);
    pthread_mutex_init(&(pool->mutex), NULL);
    pthread_cond_init(&(pool->cond), NULL);
    queue_init(&(pool->waiting));
    queue_init(&(pool->idleing));
    pool->destroying = FALSE;
    pool->thdnum = maxnum;
    for (i = 0; i < maxnum; ++i)
        pthread_create(&(pool->thdid[i]), NULL, thread_pool_func, (void *)pool);
    return pool;
}

void thread_pool_destroy(thread_pool_t *pool)
{
    uint32 i;
    queue_item_t *item = NULL;
    if (NULL == pool)
        return;
    pthread_mutex_lock(&(pool->mutex));
    if (TRUE == pool->destroying)
    {
        pthread_mutex_unlock(&(pool->mutex));
        return;
    }
    pool->destroying = TRUE;
    pthread_mutex_unlock(&(pool->mutex));
    pthread_cond_broadcast(&(pool->cond));
    for (i = 0; i < pool->thdnum; ++i)
        pthread_join(pool->thdid[i], NULL);
    queue_destroy(&(pool->waiting));
    while (FALSE == queue_empty(&(pool->waiting)))
    {
        item = queue_dequeue(&(pool->waiting));
        free(item->arg);
        free(item);
    }
    queue_destroy(&(pool->idleing));
    while (FALSE == queue_empty(&(pool->idleing)))
    {
        item = queue_dequeue(&(pool->idleing));
        free(item->arg);
        free(item);
    }
    pthread_mutex_destroy(&(pool->mutex));
    pthread_cond_destroy(&(pool->cond));
    free(pool);
}

int32 thread_pool_worker_add(thread_pool_t *pool,
                             thread_pool_worker_func func,
                             void *arg)
{
    thread_worker_t *worker = NULL;
    queue_item_t *item = NULL;
    if ((NULL == pool) || (NULL == func))
        return -1;
    pthread_mutex_lock(&(pool->mutex));
    if (TRUE == pool->destroying)
    {
        pthread_mutex_unlock(&(pool->mutex));
        return -1;
    }
    if (FALSE == queue_empty(&(pool->idleing)))
    {
        item = queue_dequeue(&(pool->idleing));
        worker = (thread_worker_t *)(item->arg);
    }
    else
    {
        worker = (thread_worker_t *)malloc(sizeof(*worker));
        item = (queue_item_t *)malloc(sizeof(*item));
        item->arg = (void *)worker;
    }
    worker->func = func;
    worker->arg = arg;
    queue_enqueue(&(pool->waiting), item);
	pthread_cond_signal(&(pool->cond));
    pthread_mutex_unlock(&(pool->mutex));
    return 0;
}