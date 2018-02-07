#include "blacklist.h"
#include "memcache.h"
#include "hashtab.h"
#include "debug.h"
#include "rwlock.h"
#include "atomic.h"
#include "log.h"

#include <linux/proc_fs.h>

static hashtab_t *sp_htab_blacklist = NULL;
static rwlock_t s_rwlock_blacklist;
static memcache_t *sp_cache_key = NULL;
static memcache_t *sp_cache_data = NULL;
static uint32 s_count = 0;
static uint32 s_maxcount = 0;
static LIST_HEAD(s_list_blacklist);
static spinlock_t s_spinlock_list_blacklist;

static uint32 blacklist_hash(const void *key)
{
    uint32 hash = 0;
    uint32 hash2;
    uint8 *mac = (uint8 *)key;
    uint32 i = 0;
    for (i = 0; i < 3; ++i)
    {
        hash2 = mac[2*i];
        hash2 = (hash2 < 8);
        hash2 |= mac[2*i + 1];
        hash += hash2;
    }
    return hash % 32;
}

static int32 blacklist_keycmp(const void *key1, const void *key2)
{
    return memcmp(key1, key2, HWADDR_SIZE);
}

static int32 blacklist_keydup(void **dst, const void *src)
{
    if (unlikely(NULL == dst || NULL == src))
        return -1;
    *dst = memcache_alloc(sp_cache_key);
    memcpy(*dst, src, sp_cache_key->bsize);
    return 0;
}

static void blacklist_keyfree(void *key)
{
    memcache_free(sp_cache_key, key);
}

static int32 blacklist_datadup(void **dst, const void *src)
{
    blacklist_t *black, *black2;
    if (unlikely(NULL == dst || NULL == src))
        return -1;
    *dst = memcache_alloc(sp_cache_data);
    black = (blacklist_t *)*dst;
    black2 = (blacklist_t *)src;
    memcpy(black->mac, black2->mac, sizeof(black->mac));
    atomic_set(&black->refcnt, 1);
    black->stats.uplink_pkts = black->stats.downlink_pkts = 0;
    spinlock_init(&black->lock);
    spinlock_lock(&s_spinlock_list_blacklist);
    list_add_tail(&black->list, &s_list_blacklist);
    ++s_count;
    spinlock_unlock(&s_spinlock_list_blacklist);
    return 0;
}

static void blacklist_datafree(void *data)
{
    blacklist_t *black = (blacklist_t *)data;
    spinlock_lock(&s_spinlock_list_blacklist);
    list_del(&black->list);
    --s_count;
    spinlock_unlock(&s_spinlock_list_blacklist);
    spinlock_destroy(&black->lock);
    bzero(black, sizeof(*black));
    memcache_free(sp_cache_data, data);
}

int32 blacklist_init(const uint32 maxcount)
{
    hashtab_operate_t ops = {
        .hash       = blacklist_hash,
        .keycmp     = blacklist_keycmp,
        .keydup     = blacklist_keydup,
        .keyfree    = blacklist_keyfree,
        .datadup    = blacklist_datadup,
        .datafree   = blacklist_datafree
    };
    
    s_count = 0;
    s_maxcount = maxcount;
    
    sp_htab_blacklist = hashtab_create(&ops);
    if (unlikely(NULL == sp_htab_blacklist))
    {
        DB_ERR("hashtab_create() call fail.");
        return -1;
    }
    rwlock_init(&s_rwlock_blacklist);
    
    sp_cache_key = memcache_create(HWADDR_SIZE, 4);
    if (unlikely(NULL == sp_cache_key))
    {
        DB_ERR("memcache_create() call fail for cache-key.");
        hashtab_destroy(sp_htab_blacklist);
        sp_htab_blacklist = NULL;
        rwlock_destroy(&s_rwlock_blacklist);
    }
    sp_cache_data = memcache_create(sizeof(blacklist_t), 4);
    if (unlikely(NULL == sp_cache_data))
    {
        DB_ERR("memcache_create() call fail for cache-key.");
        hashtab_destroy(sp_htab_blacklist);
        sp_htab_blacklist = NULL;
        rwlock_destroy(&s_rwlock_blacklist);
        memcache_destroy(sp_cache_key);
        sp_cache_key = NULL;
    }
    spinlock_init(&s_spinlock_list_blacklist);
    return 0;
}

void blacklist_destroy(void)
{
    rwlock_wrlock(&s_rwlock_blacklist);
    hashtab_destroy(sp_htab_blacklist);
    s_maxcount = 0;
    s_count = 0;
    sp_htab_blacklist = NULL;
    rwlock_wrunlock(&s_rwlock_blacklist);
    rwlock_destroy(&s_rwlock_blacklist);
    memcache_destroy(sp_cache_key);
    sp_cache_key = NULL;
    memcache_destroy(sp_cache_data);
    sp_cache_data = NULL;
    spinlock_lock(&s_spinlock_list_blacklist);
    INIT_LIST_HEAD(&s_list_blacklist);
    spinlock_unlock(&s_spinlock_list_blacklist);
    spinlock_destroy(&s_spinlock_list_blacklist);
}

int32 blacklist_add(blacklist_t *black)
{
    int32 ret = -1;
    if (unlikely(NULL == black))
    {
        LOGGING_ERR("Attempt to add invalid user information to the blacklist.");
        return -1;
    }
    
    rwlock_wrlock(&s_rwlock_blacklist);
    if (unlikely(s_count >= s_maxcount))
    {
        rwlock_wrunlock(&s_rwlock_blacklist);
        LOGGING_ERR("Add user to the blacklist table fail for blacklist full. count[%u], maxcount[%u]. "
                "mac["MACSTR"].", s_count, s_maxcount, MAC2STR(black->mac));
        return -1;
    }
    ret = hashtab_insert(sp_htab_blacklist, black->mac, black);
    if (unlikely(0 != ret))
    {
        rwlock_wrunlock(&s_rwlock_blacklist);
        LOGGING_ERR("Add user to the blacklist table fail. "
                "mac["MACSTR"].", MAC2STR(black->mac));
        return -1;
    }
    rwlock_wrunlock(&s_rwlock_blacklist);
    LOGGING_INFO("Add user to the blacklist table successfully. "
            "mac["MACSTR"].", MAC2STR(black->mac));
    return 0;
}

void blacklist_del(blacklist_t *black)
{
    if (unlikely(NULL == black))
        return;
    if (likely(atomic_read(&black->refcnt) == 1))
        smp_rmb();
    else if (likely(!atomic_dec_and_test(&black->refcnt)))
        return;
    LOGGING_INFO("Successful remove the user from the blacklist. mac["MACSTR"].", MAC2STR(black->mac));
    rwlock_wrlock(&s_rwlock_blacklist);
    hashtab_delete(sp_htab_blacklist, black->mac);
    rwlock_wrunlock(&s_rwlock_blacklist);
}

blacklist_t *blacklist_get(blacklist_t *black)
{
    if (NULL != black)
        atomic_inc(&black->refcnt);
    return black;
}

void blacklist_put(blacklist_t *black)
{
    blacklist_del(black);
}

blacklist_t *blacklist_search(const void *mac)
{
    blacklist_t *black = NULL;
    if (unlikely(NULL == mac))
        return NULL;
    rwlock_rdlock(&s_rwlock_blacklist);
    black = (blacklist_t *)hashtab_search(sp_htab_blacklist, mac);
    if (NULL != black)
        atomic_inc(&black->refcnt);
    rwlock_rdunlock(&s_rwlock_blacklist);
    return black;
}

int32 blacklist_uplink_update(blacklist_t *black)
{
    spinlock_lock(&black->lock);
    ++black->stats.uplink_pkts;
    spinlock_unlock(&black->lock);
    return 0;
}

int32 blacklist_downlink_update(blacklist_t *black)
{
    spinlock_lock(&black->lock);
    ++black->stats.downlink_pkts;
    spinlock_unlock(&black->lock);
    return 0;
}

static struct proc_dir_entry *sp_proc_blacklist = NULL;
#define PROC_BLACKLIST "blacklist"

static ssize_t blacklist_read(struct file *file, 
                              char __user *buf, 
                              size_t size, 
                              loff_t *ppos)
{
    int8 tmp[512];
    int32 len;
    int32 copyed = 0;
    struct list_head *head = (struct list_head *)file->private_data;
    blacklist_t *black;
    if (unlikely(&s_list_blacklist == head))
    {
        len = sprintf(tmp, "max:%u, count:%u\n", s_maxcount, s_count);
        len += sprintf(tmp+len, "%s  %s  %s\n", 
                    "mac", "uplink-pkts", "downlink-pkts");
        if (len > *ppos)
        {
            len = ((len - *ppos) > size) ? size : len;
            copy_to_user(buf+copyed, tmp+*ppos, len);
            copyed += len;
        }
    }
    while (likely(copyed < size))
    {
        if (unlikely(head->next == &s_list_blacklist))
            break;
        black = list_first_entry(head, blacklist_t, list);
        len = sprintf(tmp, MACSTR"  %llu  %llu\n", 
                MAC2STR(black->mac), 
                black->stats.uplink_pkts, 
                black->stats.downlink_pkts);
        if (unlikely((len + copyed) > size))
            break;
        copy_to_user(buf+copyed, tmp, len);
        copyed += len;
        head = &black->list;
        file->private_data = (void *)&black->list;
    }
    *ppos += copyed;
    return copyed;
}

static int32 blacklist_proc_open(struct inode *inode, 
                                 struct file *file)
{
    file->private_data = (void *)&s_list_blacklist;
    spinlock_lock(&s_spinlock_list_blacklist);
    return 0;
}

static int32 blacklist_proc_close(struct inode *inode, 
                                  struct file *file)
{
    spinlock_unlock(&s_spinlock_list_blacklist);
    file->private_data = NULL;
    return 0;
}

static struct file_operations s_blacklist_fileops = {
    .owner      = THIS_MODULE,
    .read       = blacklist_read,
    .open       = blacklist_proc_open,
    .release    = blacklist_proc_close
};
int32 blacklist_proc_init(struct proc_dir_entry *parent)
{
    struct proc_dir_entry *entry = proc_create(PROC_BLACKLIST, 0, parent, &s_blacklist_fileops);
    if (NULL == entry)
    {
        DB_ERR("proc_create(%s) fail!!", PROC_BLACKLIST);
        return -1;
    }
    sp_proc_blacklist = entry;
    return 0;
}

void blacklist_proc_destroy(struct proc_dir_entry *parent)
{
    if (NULL != sp_proc_blacklist)
    {
        remove_proc_entry(PROC_BLACKLIST, parent);
        sp_proc_blacklist = NULL;
    }
}
