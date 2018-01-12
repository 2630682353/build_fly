#include "whitelist.h"
#include "memcache.h"
#include "hashtab.h"
#include "debug.h"
#include "rwlock.h"
#include "atomic.h"
#include "log.h"

#include <linux/proc_fs.h>

static hashtab_t *sp_htab_whitelist = NULL;
static rwlock_t s_rwlock_whitelist;
static memcache_t *sp_cache_key = NULL;
static memcache_t *sp_cache_data = NULL;
static uint32 s_count = 0;
static uint32 s_maxcount = 0;
static LIST_HEAD(s_list_whitelist);
static spinlock_t s_spinlock_list_whitelist;

static uint32 whitelist_hash(const void *key)
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

static int32 whitelist_keycmp(const void *key1, const void *key2)
{
    return memcmp(key1, key2, HWADDR_SIZE);
}

static int32 whitelist_keydup(void **dst, const void *src)
{
    if (unlikely(NULL == dst || NULL == src))
        return -1;
    *dst = memcache_alloc(sp_cache_key);
    memcpy(*dst, src, sp_cache_key->bsize);
    return 0;
}

static void whitelist_keyfree(void *key)
{
    memcache_free(sp_cache_key, key);
}

static int32 whitelist_datadup(void **dst, const void *src)
{
    whitelist_t *white, *white2;
    if (unlikely(NULL == dst || NULL == src))
        return -1;
    *dst = memcache_alloc(sp_cache_data);
    white = (whitelist_t *)*dst;
    white2 = (whitelist_t *)src;
    memcpy(white->mac, white2->mac, sizeof(white->mac));
    atomic_set(&white->refcnt, 1);
    white->stats.uplink_pkts = white->stats.downlink_pkts = 0;
    spinlock_init(&white->lock);
    spinlock_lock(&s_spinlock_list_whitelist);
    list_add_tail(&white->list, &s_list_whitelist);
    ++s_count;
    spinlock_unlock(&s_spinlock_list_whitelist);
    return 0;
}

static void whitelist_datafree(void *data)
{
    whitelist_t *white = (whitelist_t *)data;
    spinlock_lock(&s_spinlock_list_whitelist);
    list_del(&white->list);
    --s_count;
    spinlock_unlock(&s_spinlock_list_whitelist);
    spinlock_destroy(&white->lock);
    bzero(white, sizeof(*white));
    memcache_free(sp_cache_data, data);
}

int32 whitelist_init(const uint32 maxcount)
{
    hashtab_operate_t ops = {
        .hash       = whitelist_hash,
        .keycmp     = whitelist_keycmp,
        .keydup     = whitelist_keydup,
        .keyfree    = whitelist_keyfree,
        .datadup    = whitelist_datadup,
        .datafree   = whitelist_datafree
    };
    
    s_count = 0;
    s_maxcount = maxcount;
    
    sp_htab_whitelist = hashtab_create(&ops);
    if (unlikely(NULL == sp_htab_whitelist))
    {
        DB_ERR("hashtab_create() call fail.");
        return -1;
    }
    rwlock_init(&s_rwlock_whitelist);
    
    sp_cache_key = memcache_create(HWADDR_SIZE, 4);
    if (unlikely(NULL == sp_cache_key))
    {
        DB_ERR("memcache_create() call fail for cache-key.");
        hashtab_destroy(sp_htab_whitelist);
        sp_htab_whitelist = NULL;
        rwlock_destroy(&s_rwlock_whitelist);
    }
    sp_cache_data = memcache_create(sizeof(whitelist_t), 4);
    if (unlikely(NULL == sp_cache_data))
    {
        DB_ERR("memcache_create() call fail for cache-key.");
        hashtab_destroy(sp_htab_whitelist);
        sp_htab_whitelist = NULL;
        rwlock_destroy(&s_rwlock_whitelist);
        memcache_destroy(sp_cache_key);
        sp_cache_key = NULL;
    }
    spinlock_init(&s_spinlock_list_whitelist);
    return 0;
}

void whitelist_destroy(void)
{
    rwlock_wrlock(&s_rwlock_whitelist);
    hashtab_destroy(sp_htab_whitelist);
    s_maxcount = 0;
    s_count = 0;
    sp_htab_whitelist = NULL;
    rwlock_wrunlock(&s_rwlock_whitelist);
    rwlock_destroy(&s_rwlock_whitelist);
    memcache_destroy(sp_cache_key);
    sp_cache_key = NULL;
    memcache_destroy(sp_cache_data);
    sp_cache_data = NULL;
    spinlock_lock(&s_spinlock_list_whitelist);
    INIT_LIST_HEAD(&s_list_whitelist);
    spinlock_unlock(&s_spinlock_list_whitelist);
    spinlock_destroy(&s_spinlock_list_whitelist);
}

int32 whitelist_add(whitelist_t *white)
{
    int32 ret = -1;
    if (unlikely(NULL == white))
    {
        LOGGING_ERR("Attempt to add invalid user information to the whitelist.");
        return -1;
    }
    
    rwlock_wrlock(&s_rwlock_whitelist);
    if (unlikely(s_count >= s_maxcount))
    {
        rwlock_wrunlock(&s_rwlock_whitelist);
        LOGGING_ERR("Add user to the whitelist table fail for whitelist full. count[%u], maxcount[%u]. "
                "mac["MACSTR"].", s_count, s_maxcount, MAC2STR(white->mac));
        return -1;
    }
    ret = hashtab_insert(sp_htab_whitelist, white->mac, white);
    if (unlikely(0 != ret))
    {
        rwlock_wrunlock(&s_rwlock_whitelist);
        LOGGING_ERR("Add user to the whitelist table fail. "
                "mac["MACSTR"].", MAC2STR(white->mac));
        return -1;
    }
    rwlock_wrunlock(&s_rwlock_whitelist);
    LOGGING_INFO("Add user to the whitelist table successfully. "
            "mac["MACSTR"].", MAC2STR(white->mac));
    return 0;
}

void whitelist_del(whitelist_t *white)
{
    if (unlikely(NULL == white))
        return;
    if (likely(atomic_read(&white->refcnt) == 1))
        smp_rmb();
    else if (likely(!atomic_dec_and_test(&white->refcnt)))
        return;
    LOGGING_INFO("Successful remove the user from the whitelist. mac["MACSTR"].", MAC2STR(white->mac));
    rwlock_wrlock(&s_rwlock_whitelist);
    hashtab_delete(sp_htab_whitelist, white->mac);
    rwlock_wrunlock(&s_rwlock_whitelist);
}

whitelist_t *whitelist_get(whitelist_t *white)
{
    if (NULL != white)
        atomic_inc(&white->refcnt);
    return white;
}

void whitelist_put(whitelist_t *white)
{
    whitelist_del(white);
}

whitelist_t *whitelist_search(const void *mac)
{
    whitelist_t *white = NULL;
    if (unlikely(NULL == mac))
        return NULL;
    rwlock_rdlock(&s_rwlock_whitelist);
    white = (whitelist_t *)hashtab_search(sp_htab_whitelist, mac);
    if (NULL != white)
        atomic_inc(&white->refcnt);
    rwlock_rdunlock(&s_rwlock_whitelist);
    return white;
}

int32 whitelist_uplink_update(whitelist_t *white)
{
    spinlock_lock(&white->lock);
    ++white->stats.uplink_pkts;
    spinlock_unlock(&white->lock);
    return 0;
}

int32 whitelist_downlink_update(whitelist_t *white)
{
    spinlock_lock(&white->lock);
    ++white->stats.downlink_pkts;
    spinlock_unlock(&white->lock);
    return 0;
}

static struct proc_dir_entry *sp_proc_whitelist = NULL;
#define PROC_WHITELIST "whitelist"

static ssize_t whitelist_read(struct file *file, 
                              char __user *buf, 
                              size_t size, 
                              loff_t *ppos)
{
    int8 tmp[512];
    int32 len;
    int32 copyed = 0;
    struct list_head *head = (struct list_head *)file->private_data;
    whitelist_t *white;
    if (unlikely(&s_list_whitelist == head))
    {
        len = sprintf(tmp, "max:%u, count:%u\n", s_maxcount, s_count);
        len += sprintf(tmp+len, "%-16s%-32s%-32s\n", 
                    "mac", "u-pkts", "d-pkts");
        if (len > *ppos)
        {
            len = ((len - *ppos) > size) ? size : len;
            copy_to_user(buf+copyed, tmp+*ppos, len);
            copyed += len;
        }
    }
    while (likely(copyed < size))
    {
        if (unlikely(head->next == &s_list_whitelist))
            break;
        white = list_first_entry(head, whitelist_t, list);
        len = sprintf(tmp, MACSTR" %-32llu%-32llu\n", 
                MAC2STR(white->mac), 
                white->stats.uplink_pkts, 
                white->stats.downlink_pkts);
        if (unlikely((len + copyed) > size))
            break;
        copy_to_user(buf+copyed, tmp, len);
        copyed += len;
        head = &white->list;
        file->private_data = (void *)&white->list;
    }
    *ppos += copyed;
    return copyed;
}

static int32 whitelist_proc_open(struct inode *inode, 
                                 struct file *file)
{
    file->private_data = (void *)&s_list_whitelist;
    spinlock_lock(&s_spinlock_list_whitelist);
    return 0;
}

static int32 whitelist_proc_close(struct inode *inode, 
                                  struct file *file)
{
    spinlock_unlock(&s_spinlock_list_whitelist);
    file->private_data = NULL;
    return 0;
}

static struct file_operations s_whitelist_fileops = {
    .owner      = THIS_MODULE,
    .read       = whitelist_read,
    .open       = whitelist_proc_open,
    .release    = whitelist_proc_close
};
int32 whitelist_proc_init(struct proc_dir_entry *parent)
{
#ifdef KERNEL_4_4_7
    struct proc_dir_entry *entry = proc_create(PROC_WHITELIST, 0, parent, &s_whitelist_fileops);
#elif defined KERNEL_3_2_88
    struct proc_dir_entry *entry = create_proc_entry(PROC_WHITELIST, 0, parent);
#else
    #error "undefined kernel version"
#endif
    if (NULL == entry)
    {
        DB_ERR("proc_mkdir(%s) fail!!", PROC_WHITELIST);
        return -1;
    }
    sp_proc_whitelist = entry;
    return 0;
}

void whitelist_proc_destroy(struct proc_dir_entry *parent)
{
    if (NULL != sp_proc_whitelist)
    {
        remove_proc_entry(PROC_WHITELIST, parent);
        sp_proc_whitelist = NULL;
    }
}
