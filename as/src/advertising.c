#include "advertising.h"
#include "memcache.h"
#include "spinlock.h"
#include "rwlock.h"
#include "debug.h"
#include "time.h"
#include "klog.h"
#include "http.h"

#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/ip.h>

typedef struct advertising_list_st{
    struct list_head list_ads_push;
    rwlock_t rwlock_ads_push;
    uint32 count_push;
    uint32 maxcount_push;
    
    struct list_head list_ads_embed;
    rwlock_t rwlock_ads_embed;
    uint32 count_embed;
    uint32 maxcount_embed;

    memcache_t *cache;
    spinlock_t spinlock_cache;
    BOOL inited;
}advertising_list_t;

static advertising_list_t s_ads_list = {
    .inited = FALSE,
    .cache = NULL
};

#define ADVERTISING_TIME_INTERVAL_MAX       ((uint64)-1)
#define ADVERTISING_TIME_INTERVAL_DEFAULT   ADVERTISING_TIME_INTERVAL_MAX
#define ADVERTISING_FLOW_INTERVAL_MAX       ((uint64)-1)
#define ADVERTISING_FLOW_INTERVAL_DEFAULT   ADVERTISING_FLOW_INTERVAL_MAX
static advertising_policy_t s_advertising_policy[2] = {{ADS_POLICY_NONE, ADS_OPTION_LOOPING, ADS_TYPE_PUSH, ADVERTISING_TIME_INTERVAL_DEFAULT, ADVERTISING_FLOW_INTERVAL_DEFAULT},
                                                       {ADS_POLICY_NONE, ADS_OPTION_LOOPING, ADS_TYPE_EMBED, ADVERTISING_TIME_INTERVAL_DEFAULT, ADVERTISING_FLOW_INTERVAL_DEFAULT}};

int32 advertising_init(const uint32 max_push,
                       const uint32 max_embed)
{
    if (unlikely(max_push <= 0 || max_embed <= 0))
    {
        DB_ERR("max_push(%u) <= 0 OR max_embed(%u) <= 0.", max_push, max_embed);
        return -1;
    }
    if (unlikely(s_ads_list.inited))
        return 0;
    
    INIT_LIST_HEAD(&s_ads_list.list_ads_push);
    rwlock_init(&s_ads_list.rwlock_ads_push);
    s_ads_list.count_push = 0;
    s_ads_list.maxcount_push = max_push;
    
    INIT_LIST_HEAD(&s_ads_list.list_ads_embed);
    rwlock_init(&s_ads_list.rwlock_ads_embed);
    s_ads_list.count_embed = 0;
    s_ads_list.maxcount_embed = max_embed;

    s_ads_list.cache = memcache_create(sizeof(advertising_t), max_embed+max_push);
    spinlock_init(&s_ads_list.spinlock_cache);
    s_ads_list.inited = TRUE;
    return 0;
}

void advertising_destroy(void)
{
    advertising_t *ads = NULL;

    if (unlikely(FALSE == s_ads_list.inited))
        return;
    s_ads_list.inited = FALSE;
    
    rwlock_wrlock_bh(&s_ads_list.rwlock_ads_push);
    while (!list_empty(&s_ads_list.list_ads_push))
    {
        ads = list_first_entry(&s_ads_list.list_ads_push, advertising_t, list);
        list_del(&ads->list);
        spinlock_lock(&s_ads_list.spinlock_cache);
        memcache_free(s_ads_list.cache, ads);
        spinlock_unlock(&s_ads_list.spinlock_cache);
        --(s_ads_list.count_push);
    }
    rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_push);
    rwlock_destroy(&s_ads_list.rwlock_ads_push);
    s_ads_list.maxcount_push = 0;
    
    rwlock_wrlock_bh(&s_ads_list.rwlock_ads_embed);
    while (!list_empty(&s_ads_list.list_ads_embed))
    {
        ads = list_first_entry(&s_ads_list.list_ads_embed, advertising_t, list);
        list_del(&ads->list);
        spinlock_lock(&s_ads_list.spinlock_cache);
        memcache_free(s_ads_list.cache, ads);
        spinlock_unlock(&s_ads_list.spinlock_cache);
        --(s_ads_list.count_embed);
    }
    rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_embed);
    rwlock_destroy(&s_ads_list.rwlock_ads_embed);
    s_ads_list.maxcount_embed = 0;

    memcache_destroy(s_ads_list.cache);
    spinlock_destroy(&s_ads_list.spinlock_cache);
}

int32 advertising_add(advertising_t *ads)
{
    advertising_t *ads2 = NULL;
    struct list_head *head = NULL;

    if (unlikely(FALSE == s_ads_list.inited || NULL == ads || ads->id <= 0))
    {
        LOGGING_ERR("In an attempt to add ineffective advertising.");
        return -1;
    }

    switch (ads->type)
    {
    case ADS_TYPE_PUSH:
        rwlock_wrlock_bh(&s_ads_list.rwlock_ads_push);
        if (unlikely(s_ads_list.count_push >= s_ads_list.maxcount_push))
        {
            rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_push);
            return -1;
        }
        if (likely(!list_empty(&s_ads_list.list_ads_push)))
        {
            list_for_each_entry(ads2, &s_ads_list.list_ads_push, list)
            {
                if (unlikely(ads2->id >= ads->id))
                    break;
            }
            if (unlikely(NULL != ads2 && &ads2->list != &s_ads_list.list_ads_push))
            {
                if (likely(ads2->id == ads->id))
                {
                    rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_push);
                    return -1;
                }
                else
                    head = &ads2->list;
            }
            else
                head = &s_ads_list.list_ads_push;
        }
        else
            head = &s_ads_list.list_ads_push;

        spinlock_lock(&s_ads_list.spinlock_cache);
        ads2 = (advertising_t *)memcache_alloc(s_ads_list.cache);
        spinlock_unlock(&s_ads_list.spinlock_cache);
        ASSERT(NULL != ads2);
        ads2->id = ads->id;
        ads2->type = ads->type;
        memcpy(ads2->url, ads->url, sizeof(ads2->url));
        atomic_set(&ads2->refcnt, 1);
        list_add_tail(&ads2->list, head);
        ++s_ads_list.count_push;
        rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_push);
        break;
    case ADS_TYPE_EMBED:
        rwlock_wrlock_bh(&s_ads_list.rwlock_ads_embed);
        if (unlikely(s_ads_list.count_embed >= s_ads_list.maxcount_embed))
        {
            rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_embed);
            return -1;
        }
        if (likely(!list_empty(&s_ads_list.list_ads_embed)))
        {
            list_for_each_entry(ads2, &s_ads_list.list_ads_embed, list)
            {
                if (unlikely(ads2->id >= ads->id))
                    break;
            }
            if (unlikely(NULL != ads2 && &ads2->list != &s_ads_list.list_ads_embed))
            {
                if (likely(ads2->id == ads->id))
                {
                    rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_embed);
                    return -1;
                }
                else
                    head = &ads2->list;
            }
            else
                head = &s_ads_list.list_ads_embed;
        }
        else
            head = &s_ads_list.list_ads_embed;

        spinlock_lock(&s_ads_list.spinlock_cache);
        ads2 = (advertising_t *)memcache_alloc(s_ads_list.cache);
        spinlock_unlock(&s_ads_list.spinlock_cache);
        ASSERT(NULL != ads2);
        ads2->id = ads->id;
        ads2->type = ads->type;
        memcpy(ads2->url, ads->url, sizeof(ads2->url));
        atomic_set(&ads2->refcnt, 1);
        list_add_tail(&ads2->list, head);
        ++s_ads_list.count_embed;
        rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_embed);
        break;
    default:
        LOGGING_ERR("In an attempt to add the unknown types of advertising.");
        return -1;
    }
    LOGGING_INFO("Add advertising successfully. id[%u],type[%s],url[%s].", 
            ads->id, ads_type_to_str(ads->type), ads->url);
    return 0;
}

void advertising_del_by_id_type(const uint32 id,
                                const int32 type)
{
    advertising_t *ads = NULL;
    if (unlikely(FALSE == s_ads_list.inited))
        return ;
    switch (type)
    {
    case ADS_TYPE_PUSH:
        rwlock_wrlock_bh(&s_ads_list.rwlock_ads_push);
        if (!list_empty(&s_ads_list.list_ads_push))
        {
            list_for_each_entry(ads, &s_ads_list.list_ads_push, list)
            {
                if (ads->id >= id)
                    break;
            }
            if (NULL != ads && &ads->list != &s_ads_list.list_ads_push)
            {
                if (id == ads->id && atomic_dec_and_test(&ads->refcnt))
                {
                    LOGGING_INFO("Remove advertising successfully. id[%u],type[%s],url[%s].", 
                            ads->id, ads_type_to_str(ads->type), ads->url);
                    list_del(&ads->list);
                    --s_ads_list.count_push;
                    spinlock_lock(&s_ads_list.spinlock_cache);
                    memcache_free(s_ads_list.cache, ads);
                    spinlock_unlock(&s_ads_list.spinlock_cache);
                }
            }
        }
        rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_push);
        break;
    case ADS_TYPE_EMBED:
        rwlock_wrlock_bh(&s_ads_list.rwlock_ads_embed);
        if (!list_empty(&s_ads_list.list_ads_embed))
        {
            list_for_each_entry(ads, &s_ads_list.list_ads_embed, list)
            {
                if (ads->id >= id)
                    break;
            }
            if (NULL != ads && &ads->list != &s_ads_list.list_ads_embed)
            {
                if (id == ads->id && atomic_dec_and_test(&ads->refcnt))
                {
                    LOGGING_INFO("Remove advertising successfully. id[%u],type[%s],url[%s].", 
                            ads->id, ads_type_to_str(ads->type), ads->url);
                    list_del(&ads->list);
                    --s_ads_list.count_embed;
                    spinlock_lock(&s_ads_list.spinlock_cache);
                    memcache_free(s_ads_list.cache, ads);
                    spinlock_unlock(&s_ads_list.spinlock_cache);
                }
            }
        }
        rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_embed);
        break;
    default:
        DB_ERR("Undefined advertising type[%d].", ads->type);
        LOGGING_ERR("In an attempt to remove the unknown types of advertising.");
        return ;
    }
}


void advertising_del(advertising_t *ads)
{
    if (unlikely(FALSE == s_ads_list.inited || NULL == ads))
        return;
    if (unlikely(atomic_dec_and_test(&ads->refcnt)))
        smp_rmb();
    else
        return;
    switch (ads->type)
    {
    case ADS_TYPE_PUSH:
        LOGGING_INFO("Remove advertising successfully. id[%u],type[%s],url[%s].", 
                ads->id, ads_type_to_str(ads->type), ads->url);
        rwlock_wrlock(&s_ads_list.rwlock_ads_push);
        list_del(&ads->list);
        --s_ads_list.count_push;
        spinlock_lock(&s_ads_list.spinlock_cache);
        memcache_free(s_ads_list.cache, ads);
        spinlock_unlock(&s_ads_list.spinlock_cache);
        rwlock_wrunlock(&s_ads_list.rwlock_ads_push);
        break;
    case ADS_TYPE_EMBED:
        LOGGING_INFO("Remove advertising successfully. id[%u],type[%s],url[%s].", 
                ads->id, ads_type_to_str(ads->type), ads->url);
        rwlock_wrlock(&s_ads_list.rwlock_ads_embed);
        list_del(&ads->list);
        --s_ads_list.count_embed;
        spinlock_lock(&s_ads_list.spinlock_cache);
        memcache_free(s_ads_list.cache, ads);
        spinlock_unlock(&s_ads_list.spinlock_cache);
        rwlock_wrunlock(&s_ads_list.rwlock_ads_embed);
        break;
    default:
        DB_ERR("Undefined advertising type[%d].", ads->type);
        LOGGING_ERR("In an attempt to remove the unknown types of advertising.");
        break;
    }
}

advertising_t *advertising_get(advertising_t *ads)
{
    if (likely(NULL != ads && atomic_read(&ads->refcnt) > 0))
    {
        atomic_inc(&ads->refcnt);
        return ads;
    }
    else
        return NULL;
}

void advertising_put(advertising_t *ads)
{
    advertising_del(ads);
}


static void advertising_del_bh(advertising_t *ads)
{
    if (unlikely(FALSE == s_ads_list.inited || NULL == ads))
        return;
    if (unlikely(atomic_dec_and_test(&ads->refcnt)))
        smp_rmb();
    else
        return;
    switch (ads->type)
    {
    case ADS_TYPE_PUSH:
        LOGGING_INFO("Remove advertising successfully. id[%u],type[%s],url[%s].", 
                ads->id, ads_type_to_str(ads->type), ads->url);
        rwlock_wrlock_bh(&s_ads_list.rwlock_ads_push);
        list_del(&ads->list);
        --s_ads_list.count_push;
        spinlock_lock(&s_ads_list.spinlock_cache);
        memcache_free(s_ads_list.cache, ads);
        spinlock_unlock(&s_ads_list.spinlock_cache);
        rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_push);
        break;
    case ADS_TYPE_EMBED:
        LOGGING_INFO("Remove advertising successfully. id[%u],type[%s],url[%s].", 
                ads->id, ads_type_to_str(ads->type), ads->url);
        rwlock_wrlock_bh(&s_ads_list.rwlock_ads_embed);
        list_del(&ads->list);
        --s_ads_list.count_embed;
        spinlock_lock(&s_ads_list.spinlock_cache);
        memcache_free(s_ads_list.cache, ads);
        spinlock_unlock(&s_ads_list.spinlock_cache);
        rwlock_wrunlock_bh(&s_ads_list.rwlock_ads_embed);
        break;
    default:
        DB_ERR("Undefined advertising type[%d].", ads->type);
        LOGGING_ERR("In an attempt to remove the unknown types of advertising.");
        break;
    }
}


static inline void advertising_put_bh(advertising_t *ads)
{
    advertising_del_bh(ads);
}

advertising_t *advertising_search(const uint32 id,
                                  const int32 type)
{
    advertising_t *ads = NULL;
    if (unlikely(FALSE == s_ads_list.inited))
        return NULL;
    switch (type)
    {
    case ADS_TYPE_PUSH:
        rwlock_rdlock(&s_ads_list.rwlock_ads_push);
        if (!list_empty(&s_ads_list.list_ads_push))
        {
            list_for_each_entry(ads, &s_ads_list.list_ads_push, list)
            {
                if (ads->id >= id)
                    break;
            }
            if (NULL != ads && &ads->list != &s_ads_list.list_ads_push)
            {
                if (id == ads->id && atomic_read(&ads->refcnt) > 0)
                    atomic_inc(&ads->refcnt);
                else
                    ads = NULL;
            }
        }
        rwlock_rdunlock(&s_ads_list.rwlock_ads_push);
        break;
    case ADS_TYPE_EMBED:
        rwlock_rdlock(&s_ads_list.rwlock_ads_embed);
        if (!list_empty(&s_ads_list.list_ads_embed))
        {
            list_for_each_entry(ads, &s_ads_list.list_ads_embed, list)
            {
                if (ads->id >= id)
                    break;
            }
            if (NULL != ads && &ads->list != &s_ads_list.list_ads_embed)
            {
                if (id == ads->id && atomic_read(&ads->refcnt) > 0)
                    atomic_inc(&ads->refcnt);
                else
                    ads = NULL;
            }
        }
        rwlock_rdunlock(&s_ads_list.rwlock_ads_embed);
        break;
    default:
        return NULL;
    }
    return ads;
}

static advertising_t *advertising_next(const uint32 id,
                                       const int32 type)
{
    advertising_t *ads = NULL;
    if (0 == id)
    {
        switch(type)
        {
        case ADS_TYPE_PUSH:
            rwlock_rdlock(&s_ads_list.rwlock_ads_push);
            if (!list_empty(&s_ads_list.list_ads_push))
            {
                ads = list_first_entry(&s_ads_list.list_ads_push, advertising_t, list);
                if (NULL != ads && atomic_read(&ads->refcnt) > 0)
                    atomic_inc(&ads->refcnt);
                else
                    ads = NULL;
            }
            else
                ads = NULL;
            rwlock_rdunlock(&s_ads_list.rwlock_ads_push);
            break;
        case ADS_TYPE_EMBED:
            rwlock_rdlock(&s_ads_list.rwlock_ads_embed);
            if (!list_empty(&s_ads_list.list_ads_embed))
            {
                ads = list_first_entry(&s_ads_list.list_ads_embed, advertising_t, list);
                if (NULL != ads && atomic_read(&ads->refcnt) > 0)
                    atomic_inc(&ads->refcnt);
                else
                    ads = NULL;
            }
            else
                ads = NULL;
            rwlock_rdunlock(&s_ads_list.rwlock_ads_embed);
            break;
        default:
            return NULL;
        }
    }
    else /*0 != id*/
    {
        switch (type)
        {
        case ADS_TYPE_PUSH:
            rwlock_rdlock(&s_ads_list.rwlock_ads_push);
            if (!list_empty(&s_ads_list.list_ads_push))
            {
                list_for_each_entry(ads, &s_ads_list.list_ads_push, list)
                {
                    if (ads->id >= id)
                        break;
                }
                if (NULL != ads && &ads->list != &s_ads_list.list_ads_push)
                {
                    if (id == ads->id)
                        ads = container_of(ads->list.next, advertising_t, list);
                }
                else
                    ads = list_first_entry(&s_ads_list.list_ads_push, advertising_t, list);
                if (NULL != ads && atomic_read(&ads->refcnt) > 0)
                    atomic_inc(&ads->refcnt);
                else
                    ads = NULL;
            }
            else
                ads = NULL;
            rwlock_rdunlock(&s_ads_list.rwlock_ads_push);
            break;
        case ADS_TYPE_EMBED:
            rwlock_rdlock(&s_ads_list.rwlock_ads_embed);
            if (!list_empty(&s_ads_list.list_ads_embed))
            {
                list_for_each_entry(ads, &s_ads_list.list_ads_embed, list)
                {
                    if (ads->id >= id)
                        break;
                }
                if (NULL != ads && &ads->list != &s_ads_list.list_ads_embed)
                {
                    if (id == ads->id)
                        ads = container_of(ads->list.next, advertising_t, list);
                }
                else
                    ads = list_first_entry(&s_ads_list.list_ads_embed, advertising_t, list);
                if (NULL != ads && atomic_read(&ads->refcnt) > 0)
                    atomic_inc(&ads->refcnt);
                else
                    ads = NULL;
            }
            else
                ads = NULL;
            rwlock_rdunlock(&s_ads_list.rwlock_ads_embed);
            break;
        default:
            return NULL;
        }
    }
    return ads;
}

static advertising_t *advertising_random(const int32 type)
{
    advertising_t *ads = NULL;
    uint32 index;
    switch (type)
    {
    case ADS_TYPE_PUSH:
        rwlock_rdlock(&s_ads_list.rwlock_ads_push);
        if (likely(s_ads_list.count_push > 0))
        {
            index = curtime() % s_ads_list.count_push;
            list_for_each_entry(ads, &s_ads_list.list_ads_push, list)
            {
                if (0 == index)
                    break;
                --index;
            }
            ASSERT(&ads->list != &s_ads_list.list_ads_push);
            if (NULL != ads && atomic_read(&ads->refcnt) > 0)
                atomic_inc(&ads->refcnt);
            else
                ads = NULL;
        }
        rwlock_rdunlock(&s_ads_list.rwlock_ads_push);
        break;
    case ADS_TYPE_EMBED:
        rwlock_rdlock(&s_ads_list.rwlock_ads_embed);
        if (likely(s_ads_list.count_embed > 0))
        {
            index = curtime() % s_ads_list.count_embed;
            list_for_each_entry(ads, &s_ads_list.list_ads_embed, list)
            {
                if (0 == index)
                    break;
                --index;
            }
            ASSERT(&ads->list != &s_ads_list.list_ads_embed);
            if (NULL != ads && atomic_read(&ads->refcnt) > 0)
                atomic_inc(&ads->refcnt);
            else
                ads = NULL;
        }
        rwlock_rdunlock(&s_ads_list.rwlock_ads_embed);
        break;
    default:
        return NULL;
    }
    return ads;
}

static inline advertising_t *advertising_select(const uint32 latestid,
                                                const int32 type)
{
    ASSERT(ADS_TYPE_EMBED == type || ADS_TYPE_PUSH == type);
    if (ADS_OPTION_LOOPING == s_advertising_policy[type].option)
        return advertising_next(latestid, type);
    else if (ADS_OPTION_RANDOM == s_advertising_policy[type].option)
        return advertising_random(type);
    else
        return NULL;
}

int32 advertising_redirect(struct sk_buff *skb,
                           uint32 *latestid,
                           int32 type)
{
    int32 ret;
    advertising_t *ads = NULL;

    if (FALSE == s_ads_list.inited || NULL == skb)
    {
        DB_ERR("FALSE == s_ads_list.inited(%d) || NULL == skb(%p).", s_ads_list.inited, skb);
        return -1;
    }
    ads = advertising_select(*latestid, type);
    if (NULL == ads)
    {
        DB_WAR("Don't have push advertising.");
        return -1;
    }

    ret = http_advertising_redirect(skb, ads->url);
    if (0 != ret)
    {
        DB_ERR("http_advertising_redirect() call fail.");
        return ret;
    }

    *latestid = ads->id;
    advertising_put(ads); /*need put ads*/
    return 0;
}


static struct proc_dir_entry *sp_proc_advertising_push = NULL;
#define PROC_ADVERTISING_PUSH "ads-push"
static struct proc_dir_entry *sp_proc_advertising_embed = NULL;
#define PROC_ADVERTISING_EMBED "ads-embed"

static ssize_t advertising_embed_read(struct file *file, 
                                      int8 __user *buf, 
                                      size_t size, 
                                      loff_t *ppos)
{
    int8 tmp[128];
    int32 len;
    int32 copyed = 0;
    struct list_head *head = (struct list_head *)file->private_data;
    advertising_t *ads = NULL;
    
    if (unlikely(head == &s_ads_list.list_ads_embed))
    {
        len = sprintf(tmp, "Embed Advertising Information:\nmax:%u, count:%u\n", 
                s_ads_list.maxcount_embed, s_ads_list.count_embed);
        len += sprintf(tmp+len, "%s  %s  %s\n", "id", "type", "url");
        if (len > *ppos)
        {
            len = ((len - *ppos) > size) ? size : len;
            copy_to_user(buf+copyed, tmp+*ppos, len);
            copyed += len;
        }
    }
    while (likely(copyed < size))
    {
        if (unlikely(head->next == &s_ads_list.list_ads_embed))
            break;
        ads = list_first_entry(head, advertising_t, list);
        len = snprintf(tmp, sizeof(tmp), "%u  %s  %s\n", ads->id, ads_type_to_str(ads->type), ads->url);;
        if (unlikely((len + copyed) > size))
            break;
        copy_to_user(buf+copyed, tmp, len);
        copyed += len;
        head = &ads->list;
        file->private_data = (void *)&ads->list;
    }
    *ppos += copyed;
    return copyed;
}

static int32 advertising_proc_embed_open(struct inode *inode, 
                                         struct file *file)
{
    advertising_t *ads;
    if (FALSE == s_ads_list.inited)
        return -ENODEV;
    /*在此处先将所有的ads用户的引用+1,避免在read过程中出现ads被删除,从而造成指针访问出错*/
    rwlock_rdlock_bh(&s_ads_list.rwlock_ads_embed);
    list_for_each_entry(ads, &s_ads_list.list_ads_embed, list)
    {
        advertising_get(ads);
    }
    rwlock_rdunlock_bh(&s_ads_list.rwlock_ads_embed);
    file->private_data = &s_ads_list.list_ads_embed;
    return 0;
}

static int32 advertising_proc_embed_close(struct inode *inode, 
                                          struct file *file)
{
    advertising_t *ads, *ads_next;
    /*为了保证指针的安全,此处必须使用list_for_each_entry_safe*/
    list_for_each_entry_safe(ads, ads_next, &s_ads_list.list_ads_embed, list)
    {
        advertising_put_bh(ads);
    }
    file->private_data = NULL;
    return 0;
}

static ssize_t advertising_push_read(struct file *file, 
                                     int8 __user *buf, 
                                     size_t size, 
                                     loff_t *ppos)
{
    int8 tmp[128];
    int32 len;
    int32 copyed = 0;
    struct list_head *head = (struct list_head *)file->private_data;
    advertising_t *ads = NULL;
    
    if (unlikely(head == &s_ads_list.list_ads_push))
    {
        len = sprintf(tmp, "Push Advertising Information:\nmax:%u, count:%u\n", 
                s_ads_list.maxcount_push, s_ads_list.count_push);
        len += sprintf(tmp+len, "%s  %s  %s\n", "id", "type", "url");
        if (len > *ppos)
        {
            len = ((len - *ppos) > size) ? size : len;
            copy_to_user(buf+copyed, tmp+*ppos, len);
            copyed += len;
        }
    }
    while (likely(copyed < size))
    {
        if (unlikely(head->next == &s_ads_list.list_ads_push))
            break;
        ads = list_first_entry(head, advertising_t, list);
        len = snprintf(tmp, sizeof(tmp), "%u  %s  %s\n", ads->id, ads_type_to_str(ads->type), ads->url);;
        if (unlikely((len + copyed) > size))
            break;
        copy_to_user(buf+copyed, tmp, len);
        copyed += len;
        head = &ads->list;
        file->private_data = (void *)&ads->list;
    }
    *ppos += copyed;
    return copyed;
}

static int32 advertising_proc_push_open(struct inode *inode, 
                                        struct file *file)
{
    advertising_t *ads;
    if (FALSE == s_ads_list.inited)
        return -ENODEV;
    /*在此处先将所有的ads用户的引用+1,避免在read过程中出现ads被删除,从而造成指针访问出错*/
    rwlock_rdlock_bh(&s_ads_list.rwlock_ads_push);
    list_for_each_entry(ads, &s_ads_list.list_ads_push, list)
    {
        advertising_get(ads);
    }
    rwlock_rdunlock_bh(&s_ads_list.rwlock_ads_push);
    file->private_data = &s_ads_list.list_ads_push;
    return 0;
}


static int32 advertising_proc_push_close(struct inode *inode, 
                                         struct file *file)
{
    advertising_t *ads, *ads_next;
    /*为了保证指针的安全,此处必须使用list_for_each_entry_safe*/
    list_for_each_entry_safe(ads, ads_next, &s_ads_list.list_ads_push, list)
    {
        advertising_put_bh(ads);
    }
    file->private_data = NULL;
    return 0;
}

static struct file_operations s_ads_push_fileops = {
    .owner      = THIS_MODULE,
    .read       = advertising_push_read,
    .open       = advertising_proc_push_open,
    .release    = advertising_proc_push_close
};
static struct file_operations s_ads_embed_fileops = {
    .owner      = THIS_MODULE,
    .read       = advertising_embed_read,
    .open       = advertising_proc_embed_open,
    .release    = advertising_proc_embed_close
};


int32 advertising_policy_set(const advertising_policy_t *policy)
{
    if (unlikely(NULL == policy 
        || (ADS_TYPE_EMBED != policy->type 
            && ADS_TYPE_PUSH != policy->type)))
    {
        LOGGING_ERR("Attempt to use invalid advertising policy information to update Access-Service Module's policy-set.");
        return -1;
    }
    s_advertising_policy[policy->type].policy = policy->policy;
    s_advertising_policy[policy->type].option = policy->option;
    s_advertising_policy[policy->type].type = policy->type;
    s_advertising_policy[policy->type].time_interval = policy->time_interval;
    s_advertising_policy[policy->type].flow_interval = policy->flow_interval;
    LOGGING_INFO("Update advertising policy successfully. "
            "policy[%s],option[%s],type[%s],"
            "time-interval[%llu],flow-interval[%llu].", 
            ads_policy_to_str(policy->policy), ads_option_to_str(policy->option), ads_type_to_str(policy->type), 
            policy->time_interval, policy->flow_interval);
    return 0;
}

advertising_policy_t *advertising_policy_get(const int32 type)
{
    if (unlikely(ADS_TYPE_EMBED != type && ADS_TYPE_PUSH != type))
        return NULL;
    return &s_advertising_policy[type];
}

int32 advertising_policy_query_all(void *obuf,
                                   int32 *olen)
{
    if (unlikely(NULL == obuf || NULL == olen || *olen < sizeof(s_advertising_policy)))
        return -1;
    memcpy(obuf, s_advertising_policy, sizeof(s_advertising_policy));
    *olen = sizeof(s_advertising_policy);
    return 0;
}

static struct proc_dir_entry *sp_proc_advertising_policy = NULL;
#define PROC_ADVERTISING_POLICY "ads-policy"

static ssize_t advertising_policy_read(struct file *file, 
                                       int8 __user *buf, 
                                       size_t size, 
                                       loff_t *ppos)
{
    int8 tmp[128];
    int32 len;
    int32 copyed = 0;
    uint32 index = 0;

    if (0 == *ppos)
    {
        len = sprintf(tmp, "Advertising Policy Information: policy-count[%u]\n"
                    "policy  option  type time-interval flow-interval\n",
                    ARRAY_SIZE(s_advertising_policy));
        len = ((len - *ppos) > size) ? size : len;
        copy_to_user(buf+copyed, tmp+*ppos, len);
        copyed += len;
        for (index = 0; index < ARRAY_SIZE(s_advertising_policy); ++index)
        {
            len = sprintf(tmp, "%s  %s  %s  %llu  %llu\n", 
                    ads_policy_to_str(s_advertising_policy[index].policy), 
                    ads_option_to_str(s_advertising_policy[index].option),
                    ads_type_to_str(s_advertising_policy[index].type),
                    s_advertising_policy[index].time_interval,
                    s_advertising_policy[index].flow_interval);
            copy_to_user(buf+copyed, tmp, len);
            copyed += len;
        }
    }
    *ppos += copyed;
    return copyed;
}

static struct file_operations s_ads_policy_fileops = {
    .owner      = THIS_MODULE,
    .read       = advertising_policy_read
};

int32 advertising_proc_init(struct proc_dir_entry *parent)
{
    struct proc_dir_entry *entry = proc_create(PROC_ADVERTISING_PUSH, 0, parent, &s_ads_push_fileops);
    if (NULL == entry)
    {
        DB_ERR("proc_create(%s) fail!!", PROC_ADVERTISING_PUSH);
        return -1;
    }
    sp_proc_advertising_push = entry;
    
    entry = proc_create(PROC_ADVERTISING_EMBED, 0, parent, &s_ads_embed_fileops);
    if (NULL == entry)
    {
        remove_proc_entry(PROC_ADVERTISING_PUSH, parent);
        sp_proc_advertising_push = NULL;
        DB_ERR("proc_create(%s) fail!!", PROC_ADVERTISING_EMBED);
        return -1;
    }
    sp_proc_advertising_embed = entry;
    
    entry = proc_create(PROC_ADVERTISING_POLICY, 0, parent, &s_ads_policy_fileops);
    if (NULL == entry)
    {
        remove_proc_entry(PROC_ADVERTISING_PUSH, parent);
        sp_proc_advertising_push = NULL;
        remove_proc_entry(PROC_ADVERTISING_EMBED, parent);
        sp_proc_advertising_embed = NULL;
        DB_ERR("proc_create(%s) fail!!", PROC_ADVERTISING_POLICY);
        return -1;
    }
    sp_proc_advertising_policy = entry;
    return 0;
}

void advertising_proc_destroy(struct proc_dir_entry *parent)
{
    if (NULL != sp_proc_advertising_push)
    {
        remove_proc_entry(PROC_ADVERTISING_PUSH, parent);
        sp_proc_advertising_push = NULL;
    }
    if (NULL != sp_proc_advertising_embed)
    {
        remove_proc_entry(PROC_ADVERTISING_EMBED, parent);
        sp_proc_advertising_embed = NULL;
    }
    if (NULL != sp_proc_advertising_policy)
    {
        remove_proc_entry(PROC_ADVERTISING_POLICY, parent);
        sp_proc_advertising_policy = NULL;
    }
}
