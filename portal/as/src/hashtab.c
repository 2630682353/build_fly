#include "hashtab.h"
#include "def.h"
#include "debug.h"
#include <linux/string.h>

hashtab_t *hashtab_create(const hashtab_operate_t *ops,
                          const uint32 nslot,
                          const uint32 nelem)
{
    hashtab_t *htab = NULL;
    if (NULL == ops || NULL == ops->hash || NULL == ops->keycmp)
        return NULL;
    if (!(NULL != ops->keydup && NULL != ops->keyfree))
        return NULL;
    if (!(NULL != ops->datadup && NULL != ops->datafree))
        return NULL;
    htab = (hashtab_t *)malloc(sizeof(*htab));
    bzero(htab, sizeof(*htab));
    memcpy(&htab->hash_ops, ops, sizeof(*ops));
    INIT_LIST_HEAD(&htab->slots);
    htab->cache_slots = memcache_create(sizeof(hashtab_slot_t), nslot);
    htab->cache_elems = memcache_create(sizeof(hashtab_elem_t), nelem);
    return htab;
}

void hashtab_destroy(hashtab_t *htab)
{
    hashtab_slot_t *slot = NULL;
    hashtab_elem_t *elem = NULL;
    if (NULL == htab)
        return;
    while (!list_empty(&htab->slots))
    {
        slot = list_first_entry(&htab->slots, hashtab_slot_t, list);
        list_del(&slot->list);
        while (!list_empty(&slot->elems))
        {
            elem = list_first_entry(&slot->elems, hashtab_elem_t, list);
            list_del(&elem->list);
            if (NULL != htab->hash_ops.keyfree)
                htab->hash_ops.keyfree(elem->key);
            if (NULL != htab->hash_ops.datafree)
                htab->hash_ops.datafree(elem->data);
            memcache_free(htab->cache_elems, (void *)elem);
        }
        memcache_free(htab->cache_slots, (void *)slot);
    }
    memcache_destroy(htab->cache_slots);
    memcache_destroy(htab->cache_elems);
    free(htab);
}

int32 hashtab_insert(hashtab_t *htab,
                     const void *key,
                     const void *data)
{
    hashtab_slot_t *slot = NULL;
    hashtab_slot_t *slot2 = NULL;
    hashtab_elem_t *elem = NULL;
    hashtab_elem_t *elem2 = NULL;
    uint32 hash;
    int32 ret = 0;
    if (NULL == htab || NULL == key || NULL == data)
        return -1;
    ASSERT(NULL != htab->hash_ops.hash && NULL != htab->hash_ops.keycmp);
    hash = htab->hash_ops.hash(key);
    if (!list_empty(&htab->slots))
    {
        list_for_each_entry(slot, &htab->slots, list)
        {
            if (hash <= slot->hash)                
                break;
        }
        if (&slot->list != &htab->slots)
        {
            if (hash == slot->hash)
            {
                if (!list_empty(&slot->elems))
                {
                    list_for_each_entry(elem, &slot->elems, list)
                    {
                        ret = htab->hash_ops.keycmp(key, elem->key);
                        if (ret > 0)
                            continue;
                        else if (0 == ret)
                            return 0; /*already exist. return succeed.*/
                        else
                            break;
                    }
                    elem2 = (hashtab_elem_t *)memcache_alloc(htab->cache_elems);
                    list_add_tail(&elem2->list, &elem->list);
                    if (NULL != htab->hash_ops.keydup)
                    {
                        ret = htab->hash_ops.keydup(&elem2->key, key);
                        if (0 != ret)
                        {
                            list_del(&elem2->list);
                            memcache_free(htab->cache_elems, elem2);
                            return -1;
                        }
                    }
                    else
                        elem2->key = (void *)key;
                    if (NULL != htab->hash_ops.datadup)
                    {
                        ret = htab->hash_ops.datadup(&elem2->data, data);
                        if (0 != ret)
                        {
                            list_del(&elem2->list);
                            if (NULL != htab->hash_ops.keyfree)
                                htab->hash_ops.keyfree(elem2->key);
                            memcache_free(htab->cache_elems, elem2);
                            return -1;
                        }
                    }
                    else
                        elem2->data = (void *)data;
                }
                else /*list_empty(&slot->elems)*/
                {
                    elem2 = (hashtab_elem_t *)memcache_alloc(htab->cache_elems);
                    list_add_tail(&elem2->list, &slot->elems);
                    if (NULL != htab->hash_ops.keydup)
                    {
                        ret = htab->hash_ops.keydup(&elem2->key, key);
                        if (0 != ret)
                        {
                            list_del(&elem2->list);
                            memcache_free(htab->cache_elems, elem2);
                            return -1;
                        }
                    }
                    else
                        elem2->key = (void *)key;
                    if (NULL != htab->hash_ops.datadup)
                    {
                        ret = htab->hash_ops.datadup(&elem2->data, data);
                        if (0 != ret)
                        {
                            list_del(&elem2->list);
                            if (NULL != htab->hash_ops.keyfree)
                                htab->hash_ops.keyfree(elem2->key);
                            memcache_free(htab->cache_elems, elem2);
                            return -1;
                        }
                    }
                    else
                        elem2->data = (void *)data;
                }
            }
            else /*hash < slot->hash*/
            {
                slot2 = (hashtab_slot_t *)memcache_alloc(htab->cache_slots);
                list_add_tail(&slot2->list, &slot->list);
                slot2->hash = hash;
                INIT_LIST_HEAD(&slot2->elems);
                elem2 = (hashtab_elem_t *)memcache_alloc(htab->cache_elems);
                list_add_tail(&elem2->list, &slot2->elems);
                if (NULL != htab->hash_ops.keydup)
                {
                    ret = htab->hash_ops.keydup(&elem2->key, key);
                    if (0 != ret)
                    {
                        list_del(&elem2->list);
                        memcache_free(htab->cache_elems, elem2);
                        list_del(&slot2->list);
                        memcache_free(htab->cache_slots, slot2);
                        return -1;
                    }
                }
                else
                    elem2->key = (void *)key;
                if (NULL != htab->hash_ops.datadup)
                {
                    ret = htab->hash_ops.datadup(&elem2->data, data);
                    if (0 != ret)
                    {
                        list_del(&elem2->list);
                        if (NULL != htab->hash_ops.keyfree)
                            htab->hash_ops.keyfree(elem2->key);
                        memcache_free(htab->cache_elems, elem2);
                        list_del(&slot2->list);
                        memcache_free(htab->cache_slots, slot2);
                        return -1;
                    }
                }
                else
                    elem2->data = (void *)data;
            }
        }
        else /*&slot->list == &htab->slots*/
        {
            slot2 = (hashtab_slot_t *)memcache_alloc(htab->cache_slots);
            list_add_tail(&slot2->list, &htab->slots);
            slot2->hash = hash;
            INIT_LIST_HEAD(&slot2->elems);
            elem2 = (hashtab_elem_t *)memcache_alloc(htab->cache_elems);
            list_add_tail(&elem2->list, &slot2->elems);
            if (NULL != htab->hash_ops.keydup)
            {
                ret = htab->hash_ops.keydup(&elem2->key, key);
                if (0 != ret)
                {
                    list_del(&elem2->list);
                    memcache_free(htab->cache_elems, elem2);
                    list_del(&slot2->list);
                    memcache_free(htab->cache_slots, slot2);
                    return -1;
                }
            }
            else
                elem2->key = (void *)key;
            if (NULL != htab->hash_ops.datadup)
            {
                ret = htab->hash_ops.datadup(&elem2->data, data);
                if (0 != ret)
                {
                    list_del(&elem2->list);
                    if (NULL != htab->hash_ops.keyfree)
                        htab->hash_ops.keyfree(elem2->key);
                    memcache_free(htab->cache_elems, elem2);
                    list_del(&slot2->list);
                    memcache_free(htab->cache_slots, slot2);
                    return -1;
                }
            }
            else
                elem2->data = (void *)data;
        }
    }
    else /*list_empty(&htab->slots)*/
    {
        slot2 = (hashtab_slot_t *)memcache_alloc(htab->cache_slots);
        list_add_tail(&slot2->list, &htab->slots);
        slot2->hash = hash;
        INIT_LIST_HEAD(&slot2->elems);
        elem2 = (hashtab_elem_t *)memcache_alloc(htab->cache_elems);
        list_add_tail(&elem2->list, &slot2->elems);
        if (NULL != htab->hash_ops.keydup)
        {
            ret = htab->hash_ops.keydup(&elem2->key, key);
            if (0 != ret)
            {
                list_del(&elem2->list);
                memcache_free(htab->cache_elems, elem2);
                list_del(&slot2->list);
                memcache_free(htab->cache_slots, slot2);
                return -1;
            }
        }
        else
            elem2->key = (void *)key;
        if (NULL != htab->hash_ops.datadup)
        {
            ret = htab->hash_ops.datadup(&elem2->data, data);
            if (0 != ret)
            {
                list_del(&elem2->list);
                if (NULL != htab->hash_ops.keyfree)
                    htab->hash_ops.keyfree(elem2->key);
                memcache_free(htab->cache_elems, elem2);
                list_del(&slot2->list);
                memcache_free(htab->cache_slots, slot2);
                return -1;
            }
        }
        else
            elem2->data = (void *)data;
    }
    return 0;
}

void hashtab_delete(hashtab_t *htab,
                    const void *key)
{
    hashtab_slot_t *slot = NULL;
    hashtab_elem_t *elem = NULL;
    uint32 hash;
    if (NULL == htab || NULL == key)
        return;
    ASSERT(NULL != htab->hash_ops.hash && NULL != htab->hash_ops.keycmp);
    if (!list_empty(&htab->slots))
    {
        hash = htab->hash_ops.hash(key);
        list_for_each_entry(slot, &htab->slots, list)
        {
            if (hash <= slot->hash)                
                break;
        }
        if (&slot->list != &htab->slots 
            && hash == slot->hash)
        {
            if (!list_empty(&slot->elems))
            {
                int32 ret = 0;
                list_for_each_entry(elem, &slot->elems, list)
                {
                    ret = htab->hash_ops.keycmp(key, elem->key);
                    if (ret > 0)
                        continue;
                    else if (0 == ret)
                    {
                        list_del(&elem->list);
                        if (NULL != htab->hash_ops.keyfree)
                            htab->hash_ops.keyfree(elem->key);
                        if (NULL != htab->hash_ops.datafree)
                            htab->hash_ops.datafree(elem->data);
                        memcache_free(htab->cache_elems, (void *)elem);
                        if (list_empty(&slot->elems))
                        {
                            list_del(&slot->list);
                            memcache_free(htab->cache_slots, (void *)slot);
                        }
                        break;
                    }
                    else
                        break;
                }
            }
        }
    }
}

void *hashtab_search(hashtab_t *htab,
                     const void *key)
{
    hashtab_slot_t *slot = NULL;
    hashtab_elem_t *elem = NULL;
    uint32 hash;
    if (NULL == htab || NULL == key)
        return NULL;
    ASSERT(NULL != htab->hash_ops.hash && NULL != htab->hash_ops.keycmp);
    if (!list_empty(&htab->slots))
    {
        hash = htab->hash_ops.hash(key);
        list_for_each_entry(slot, &htab->slots, list)
        {
            if (hash <= slot->hash)                
                break;
        }
        if (&slot->list != &htab->slots 
            && hash == slot->hash)
        {
            if (!list_empty(&slot->elems))
            {
                int32 ret = 0;
                list_for_each_entry(elem, &slot->elems, list)
                {
                    ret = htab->hash_ops.keycmp(key, elem->key);
                    if (ret > 0)
                        continue;
                    else if (0 == ret)
                        return elem->data;
                    else
                        break;
                }
            }
        }
    }
    return NULL;
}

int32 hashtab_foreach(hashtab_t *htab,
                      int (*apply)(const void *key, void *data, void *args),
                      void *args)
{
    hashtab_slot_t *slot = NULL;
    hashtab_elem_t *elem = NULL;
    int32 ret = -1;
    if (NULL == htab || NULL == apply)
        return -1;
    list_for_each_entry(slot, &htab->slots, list)
    {
        list_for_each_entry(elem, &slot->elems, list)
        {
            ret = apply(elem->key, elem->data, args);
            if (0 != ret)
                return ret;
        }
    }
    return 0;
}
