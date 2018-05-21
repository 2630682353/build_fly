#ifndef __BUFFER_QUEUE_H__
#define __BUFFER_QUEUE_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"
#include "memcache.h"
#include <pthread.h>

typedef struct buffer_queue_st{
    buffer_t *head;
    buffer_t *tail;
    uint32 buffnum;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
    uint32 buffsize;
    memcache_t *cache;
    pthread_mutex_t cache_mutex;
}buffer_queue_t;
#define BUFFER_QUEUE_BUFFER_MAXSIZE         ((32*1024) - sizeof(buffer_t))

static inline buffer_t *buffer_queue_buffer_alloc(buffer_queue_t *queue)
{
    buffer_t *buf = NULL;
    if (NULL == queue)
        return NULL;
    pthread_mutex_lock(&queue->cache_mutex);
    buf = (buffer_t *)memcache_alloc(queue->cache);
    pthread_mutex_unlock(&queue->cache_mutex);
    if (NULL == buf)
        return NULL;
    buf->buf = (int8 *)(buf + 1);
    buf->size = queue->buffsize;
    buf->offset = buf->len = 0;
    buf->next = NULL;
    return buf;
}

static inline buffer_t *buffer_queue_buffer_reset(buffer_queue_t *queue,
                                                  buffer_t *buf)
{
    if (NULL == queue)
        return NULL;
    buf->buf = (int8 *)(buf + 1);
    buf->size = queue->buffsize;
    buf->offset = buf->len = 0;
    buf->next = NULL;
    return buf;
}

static inline void buffer_queue_buffer_free(buffer_queue_t *queue,
                                            buffer_t *buf)
{
    if (NULL == queue)
        return;
    pthread_mutex_lock(&queue->cache_mutex);
    memcache_free(queue->cache, buf);
    pthread_mutex_unlock(&queue->cache_mutex);
}

static inline int32 buffer_queue_enqueue(buffer_queue_t *queue,
                                         buffer_t *buf)
{
    if (NULL == queue || NULL == buf)
        return -1;
    pthread_mutex_lock(&queue->mutex);
    if (0 == queue->buffnum)
    {
        queue->head = queue->tail = buf;
        queue->buffnum = 1;
        pthread_cond_signal(&queue->cond);
    }
    else
    {
        queue->tail->next = buf;
        queue->tail = buf;
        ++queue->buffnum;
    }
    pthread_mutex_unlock(&queue->mutex);
    return 0;
}

static inline buffer_t *buffer_queue_dequeue(buffer_queue_t *queue)
{
    buffer_t *buf;
    if (NULL == queue)
        return NULL;
    pthread_mutex_lock(&queue->mutex);
    if (0 == queue->buffnum)
    {
        pthread_cond_wait(&queue->cond, &queue->mutex);
        if (0 == queue->buffnum)
        {
            pthread_mutex_unlock(&queue->mutex);
            return NULL;
        }
    }
    buf = queue->head;
    --queue->buffnum;
    if (0 == queue->buffnum)
    {
        queue->head = NULL;
        queue->tail = NULL;
    }
    else
        queue->head = queue->head->next;
    pthread_mutex_unlock(&queue->mutex);
    return buf;
}

static inline buffer_queue_t *buffer_queue_create(const uint32 buffsize)
{
    buffer_queue_t *queue;
    uint32 bsize = (buffsize <= 0 || buffsize >= BUFFER_QUEUE_BUFFER_MAXSIZE) ? BUFFER_QUEUE_BUFFER_MAXSIZE : buffsize;
    queue = (buffer_queue_t *)malloc(sizeof(*queue));
    if (NULL == queue)
        return NULL;
    queue->cache = memcache_create(bsize+sizeof(buffer_t), 4);
    if (NULL == queue->cache)
    {
        free(queue);
        return NULL;
    }
    queue->buffsize = bsize;
    pthread_mutex_init(&queue->cache_mutex, NULL);
    queue->head = NULL;
    queue->tail = NULL;
    queue->buffnum = 0;
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->cond, NULL);
    return queue;
}

static inline void buffer_queue_destroy(buffer_queue_t *queue)
{
    if (NULL == queue)
        return ;
    pthread_cond_destroy(&queue->cond);
    pthread_mutex_destroy(&queue->mutex);
    pthread_mutex_destroy(&queue->cache_mutex);
    memcache_destroy(queue->cache);
    free(queue);
}


#ifdef  __cplusplus
}
#endif

#endif /*__BUFFER_QUEUE_H__*/
