#ifndef __MEMCACHE_H__
#define __MEMCACHE_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/list.h>
#include "type.h"

typedef struct memcache_slab_st{
    struct list_head list;
    void *buf;
}memcache_slab_t;

typedef struct memcache_st{
    struct list_head slabs;
    struct list_head fslabs;
    uint32 fnslabs;
    uint32 bsize;
}memcache_t;

memcache_t *memcache_create(const uint32 bsize,
                            const uint32 nslabs);
void memcache_destroy(memcache_t *cache);
void *memcache_alloc(memcache_t *cache);
void memcache_free(memcache_t *cache,
                   void *buf);

#ifdef  __cplusplus
}
#endif

#endif /*__MEMCACHE_H__*/
