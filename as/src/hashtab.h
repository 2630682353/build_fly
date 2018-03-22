#ifndef __HASHTAB_H__
#define __HASHTAB_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"
#include "memcache.h"

typedef struct hashtab_elem_st{
    struct list_head list;  /*slot's element list*/
    void *key;              /*hash key*/
    void *data;             /*data*/
}hashtab_elem_t;

typedef struct hashtab_slot_st{
    struct list_head list;  /*hash table slots list*/
    uint32 hash;            /*hash value*/
    struct list_head elems; /*slot's element list*/
}hashtab_slot_t;

typedef struct hashtab_operate_st{
    /*hash function*/
    uint32 (*hash)(const void *key);
    /*key comparison function*/
    int32 (*keycmp)(const void *key1, const void *key2);
    /*key dup function*/
    int32 (*keydup)(void **dst, const void *src);
    /*key free function*/
    void (*keyfree)(void *key);
    /*data dup function*/
    int32 (*datadup)(void **dst, const void *src);
    /*data free function*/
    void (*datafree)(void *data);
}hashtab_operate_t;

typedef struct hashtab_st{
    struct list_head slots;         /*hash table slots list*/
    hashtab_operate_t hash_ops;     /*hash table operates*/
    memcache_t *cache_slots;        /*memory cache for slots*/
    memcache_t *cache_elems;        /*memory cache for elements*/
}hashtab_t;

hashtab_t *hashtab_create(const hashtab_operate_t *ops,
                          const uint32 nslot,
                          const uint32 nelem);
void hashtab_destroy(hashtab_t *htab);
int32 hashtab_insert(hashtab_t *htab,
                     const void *key,
                     const void *data);
void hashtab_delete(hashtab_t *htab,
                    const void *key);
void *hashtab_search(hashtab_t *htab,
                     const void *key);
int32 hashtab_foreach(hashtab_t *htab,
                      int (*apply)(const void *key, void *data, void *args),
                      void *args);

#ifdef  __cplusplus
}
#endif

#endif /*__HASHTAB_H__*/
