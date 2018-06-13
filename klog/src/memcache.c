#include "memcache.h"
#include "def.h"

#define MEMCACHE_FNSLABS_INCREMENT      (4)
#define MEMCACHE_FNSLABS_MAXCOUNT       (16)

static memcache_slab_t *_memcache_slab_alloc(memcache_t *cache)
{
    memcache_slab_t *slab = (memcache_slab_t *)malloc(ALIGN_4_BYTES(sizeof(*slab) + cache->bsize));
    slab->buf = (void *)(slab+1);
    return slab;
}

static void _memcache_slab_free(memcache_slab_t *slab)
{
    free(slab);
}

memcache_t *memcache_create(const uint32 bsize,
                            const uint32 nslabs)
{
    memcache_t *cache = NULL;
    memcache_slab_t *slab = NULL;
    uint32 fnslabs = nslabs > MEMCACHE_FNSLABS_MAXCOUNT ? MEMCACHE_FNSLABS_MAXCOUNT : nslabs;
    if (bsize <= 0)
        return NULL;
    cache = (memcache_t *)malloc(sizeof(*cache));
    cache->bsize = bsize;
    cache->fnslabs = 0;
    cache->nslabs = 0;
    INIT_LIST_HEAD(&cache->slabs);
    INIT_LIST_HEAD(&cache->fslabs);
    while (cache->fnslabs < fnslabs)
    {
        slab = _memcache_slab_alloc(cache);
        list_add(&slab->list, &cache->fslabs);
        ++cache->fnslabs;
    }
    return cache;
}

void memcache_destroy(memcache_t *cache)
{
    if (NULL != cache)
    {
        memcache_slab_t *slab = NULL;
        while (!list_empty(&cache->slabs))
        {
            slab = list_first_entry(&cache->slabs, memcache_slab_t, list);
            list_del(&slab->list);
            _memcache_slab_free(slab);
            --cache->nslabs;
        }
        while (!list_empty(&cache->fslabs))
        {
            slab = list_first_entry(&cache->fslabs, memcache_slab_t, list);
            list_del(&slab->list);
            _memcache_slab_free(slab);
            --cache->fnslabs;
        }
        free(cache);
    }
}

void *memcache_alloc(memcache_t *cache)
{
    memcache_slab_t *slab = NULL;
    if (NULL == cache)
        return NULL;
    if (cache->fnslabs <= 0)
    {
        while (cache->fnslabs < MEMCACHE_FNSLABS_INCREMENT)
        {
            slab = _memcache_slab_alloc(cache);;
            list_add_tail(&slab->list, &cache->fslabs);
            ++cache->fnslabs;
        }
    }
    slab = list_first_entry(&cache->fslabs, memcache_slab_t, list);
    list_del(&slab->list);
    list_add_tail(&slab->list, &cache->slabs);
    --cache->fnslabs;
    ++cache->nslabs;
    return slab->buf;
}

void memcache_free(memcache_t *cache,
                   void *buf)
{
    if (NULL != cache && NULL != buf)
    {
        memcache_slab_t *slab = container_of((void *)(((long)buf)-sizeof(void *)), memcache_slab_t, buf);
        list_del(&slab->list);
        --cache->nslabs;
        if (cache->fnslabs < MEMCACHE_FNSLABS_MAXCOUNT)
        {
            list_add_tail(&slab->list, &cache->fslabs);
            ++cache->fnslabs;
        }
        else
            _memcache_slab_free(slab);
    }
}
