#include "authenticated.h"
#include "advertising.h"
#include "hashtab.h"
#include "memcache.h"
#include "time.h"
#include "rwlock.h"
#include "spinlock.h"
#include "debug.h"
#include "http.h"
#include "config.h"
#include "log.h"

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <net/ip.h>

static hashtab_t *sp_htab_auth = NULL;
static rwlock_t s_rwlock_htab_auth;
static memcache_t *sp_cache_key = NULL;
static memcache_t *sp_cache_data = NULL;
/*以auth->time.latest按从小到大的顺序排序*/
static LIST_HEAD(s_list_auth);
static spinlock_t s_spinlock_list_auth;
#define DEFAULT_AUTH_MAX_COUNT  (1024)
static uint32 s_count = 0;
static uint32 s_maxcount = DEFAULT_AUTH_MAX_COUNT;
struct task_struct *sp_kthd_auth = NULL;

static uint32 authenticated_hash(const void *key)
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
    return hash % 128;
}

static int32 authenticated_keycmp(const void *key1,
                                  const void *key2)
{
    return memcmp(key1, key2, HWADDR_SIZE);
}

static int32 authenticated_keydup(void **dst,
                                  const void *src)
{
    if (unlikely(NULL == dst || NULL == src))
        return -1;
    *dst = memcache_alloc(sp_cache_key);
    memcpy(*dst, src, sp_cache_key->bsize);
    return 0;
}

static void authenticated_keyfree(void *key)
{
    memcache_free(sp_cache_key, key);
}

static int32 authenticated_datadup(void **dst, const void *src)
{
    authenticated_t *auth, *auth2;
    if (unlikely(NULL == dst || NULL == src))
        return -1;
    *dst = memcache_alloc(sp_cache_data);
    bzero(*dst, sp_cache_data->bsize);
    auth = (authenticated_t *)*dst;
    auth2 = (authenticated_t *)src;
    atomic_set(&auth->refcnt, 1);
    auth->time.start = auth->time.latest = curtime();
    memcpy(auth->mac, auth2->mac, sizeof(auth->mac));
    auth->ipaddr = auth2->ipaddr;
    memcpy(&auth->acct, &auth2->acct, sizeof(auth->acct));
    spinlock_init(&auth->lock);
    spinlock_lock(&s_spinlock_list_auth);
    list_add_tail(&auth->list,&s_list_auth);
    ++s_count;
    spinlock_unlock(&s_spinlock_list_auth);
    return 0;
}

static void authenticated_datafree(void *data)
{
    authenticated_t *auth = (authenticated_t *)data;
    spinlock_lock(&s_spinlock_list_auth);
    list_del(&auth->list);
    --s_count;
    spinlock_unlock(&s_spinlock_list_auth);
    spinlock_destroy(&auth->lock);
    bzero(auth, sizeof(*auth));
    memcache_free(sp_cache_data, auth);
}

#define AUTHENTICATED_BURNED_TIME_MAX       (10*60)//(24*60*60)
#define AUTHENTICATED_KEEPALIVE_TIME_MAX    (60)//(10*60)
#define AUTHENTICATED_KTHREAD_SLEEP_MSECS   (1000)

static int32 authenticated_burned_check_func(void *data)
{
    authenticated_t *auth = NULL;
    while (!kthread_should_stop())
    {
        /*keepalive timeout OR burned timeout check*/
        rwlock_rdlock(&s_rwlock_htab_auth);
        spinlock_lock(&s_spinlock_list_auth);
        if (likely(!list_empty(&s_list_auth)))
        {
            uint64 now = curtime();
            list_for_each_entry(auth, &s_list_auth, list)
            {
                if ((now - auth->time.latest) >= AUTHENTICATED_KEEPALIVE_TIME_MAX
                    || (now - auth->time.start) >= AUTHENTICATED_BURNED_TIME_MAX)
                {
                    /*DB_INF("now[%llu], latest[%llu], start[%llu], "
                        "keepalive-timeout[%u], burned-timeout[%u].",
                        now, auth->time.latest, auth->time.start, 
                        AUTHENTICATED_KEEPALIVE_TIME_MAX, 
                        AUTHENTICATED_BURNED_TIME_MAX);*/
                    authenticated_get(auth);
                    break;
                }
            }
            auth = (&s_list_auth == &auth->list) ? NULL : auth;
        }
        else
            auth = NULL;
        spinlock_unlock(&s_spinlock_list_auth);
        rwlock_rdunlock(&s_rwlock_htab_auth);
        
        if (NULL != auth)
        {
            config_authenticated_timeout(auth->mac); /*notify AAA-Client delete timeout user.*/
            authenticated_put(auth);
            authenticated_del(auth);
            continue;
        }
        else
            msleep_interruptible(AUTHENTICATED_KTHREAD_SLEEP_MSECS);
    }
    return 0;
}

int32 authenticated_init(const uint32 maxcount)
{
    hashtab_operate_t ops = {
        .hash       = authenticated_hash,
        .keycmp     = authenticated_keycmp,
        .keydup     = authenticated_keydup,
        .keyfree    = authenticated_keyfree,
        .datadup    = authenticated_datadup,
        .datafree   = authenticated_datafree
    };
    if (maxcount <= 0)
        return -1;
    s_maxcount = maxcount;
    s_count = 0;
    sp_htab_auth = hashtab_create(&ops);
    if (unlikely(NULL == sp_htab_auth))
    {
        DB_ERR("hashtab_create() call fail.");
        return -1;
    }
    rwlock_init(&s_rwlock_htab_auth);
    
    sp_cache_key = memcache_create(HWADDR_SIZE, 4);
    if (unlikely(NULL == sp_cache_key))
    {
        DB_ERR("memcache_create() call fail for cache-key.");
        rwlock_destroy(&s_rwlock_htab_auth);
        hashtab_destroy(sp_htab_auth);
        sp_htab_auth = NULL;
        return -1;
    }
    
    sp_cache_data = memcache_create(sizeof(authenticated_t), 4);
    if (unlikely(NULL == sp_cache_data))
    {
        DB_ERR("memcache_create() call fail for cache-data.");
        rwlock_destroy(&s_rwlock_htab_auth);
        hashtab_destroy(sp_htab_auth);
        sp_htab_auth = NULL;
        memcache_destroy(sp_cache_key);
        sp_cache_key = NULL;
        return -1;
    }

    spinlock_init(&s_spinlock_list_auth);
    sp_kthd_auth = kthread_run(authenticated_burned_check_func, NULL, "auth-burned-kthread");
    if (unlikely(NULL == sp_kthd_auth))
    {
        DB_ERR("memcache_create() call fail for cache-data.");
        rwlock_destroy(&s_rwlock_htab_auth);
        hashtab_destroy(sp_htab_auth);
        sp_htab_auth = NULL;
        memcache_destroy(sp_cache_key);
        sp_cache_key = NULL;
        memcache_destroy(sp_cache_data);
        sp_cache_data = NULL;
        spinlock_destroy(&s_spinlock_list_auth);
        return -1;
    }
    return 0;
}

void authenticated_destroy(void)
{
    rwlock_wrlock(&s_rwlock_htab_auth);
    hashtab_destroy(sp_htab_auth);
    sp_htab_auth = NULL;
    s_maxcount = DEFAULT_AUTH_MAX_COUNT;
    s_count = 0;
    rwlock_wrunlock(&s_rwlock_htab_auth);
    rwlock_destroy(&s_rwlock_htab_auth);

    memcache_destroy(sp_cache_key);
    sp_cache_key = NULL;

    memcache_destroy(sp_cache_data);
    sp_cache_data = NULL;
    
    spinlock_lock(&s_spinlock_list_auth);
    INIT_LIST_HEAD(&s_list_auth);
    spinlock_unlock(&s_spinlock_list_auth);
    spinlock_destroy(&s_spinlock_list_auth);
    
    kthread_stop(sp_kthd_auth);
}

int32 authenticated_add(authenticated_t *auth)
{
    int32 ret = -1;
    if (unlikely(NULL == auth))
    {
        LOGGING_ERR("Attempt to add invalid authentication user information to the users table.");
        return -1;
    }
    rwlock_wrlock(&s_rwlock_htab_auth);
    if (unlikely(s_count >= s_maxcount))
    {
        authenticated_t *auth2;
        auth2 = list_first_entry(&s_list_auth, authenticated_t, list);
        hashtab_delete(sp_htab_auth, auth2->mac);
    }
    ret = hashtab_insert(sp_htab_auth, auth->mac, auth);
    if (unlikely(0 != ret))
    {
        rwlock_wrunlock(&s_rwlock_htab_auth);
        DB_ERR("hashtab_insert() call fail.");
        LOGGING_ERR("Add authentication user to the user's table fail. "
                "mac["MACSTR"], acct_status:%d, acct_policy:%d, "
                "total_seconds:%llu, total_flows:%llu",
                MAC2STR(auth->mac), auth->acct.status, auth->acct.policy, 
                auth->acct.valid_time, auth->acct.valid_flow);
        return -1;
    }
    rwlock_wrunlock(&s_rwlock_htab_auth);
    LOGGING_INFO("Add authentication user to the user's table successfully. "
            "mac["MACSTR"], acct_status:%d, acct_policy:%d, "
            "total_seconds:%llu, total_flows:%llu",
            MAC2STR(auth->mac), auth->acct.status, auth->acct.policy, 
            auth->acct.valid_time, auth->acct.valid_flow);
    return 0;
}

void authenticated_del(authenticated_t *auth)
{
    if (unlikely(NULL == auth))
        return;
    if (likely(atomic_read(&auth->refcnt) == 1))
        smp_rmb();
    else if (likely(!atomic_dec_and_test(&auth->refcnt)))
        return;
    LOGGING_INFO("Successful remove the user from the authenticated user list. mac["MACSTR"].",MAC2STR(auth->mac));
    rwlock_wrlock(&s_rwlock_htab_auth);
    hashtab_delete(sp_htab_auth, auth->mac);
    rwlock_wrunlock(&s_rwlock_htab_auth);
}

authenticated_t *authenticated_get(authenticated_t *auth)
{
    if (likely(NULL != auth))
        atomic_inc(&auth->refcnt);
    return auth;
}

void authenticated_put(authenticated_t *auth)
{
    authenticated_del(auth);
}

authenticated_t *authenticated_search(const void *mac)
{
    authenticated_t *auth = NULL;
    if (unlikely(NULL == mac))
        return NULL;
    rwlock_rdlock(&s_rwlock_htab_auth);
    auth = (authenticated_t *)hashtab_search(sp_htab_auth, mac);
    if (NULL != auth)
        atomic_inc(&auth->refcnt);
    rwlock_rdunlock(&s_rwlock_htab_auth);
    return auth;
}

int32 authenticated_uplink_skb_update(authenticated_t *auth,
                                      struct sk_buff *skb)
{
    int32 ret = -1;
    struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph = (struct iphdr *)(ethh+1);
    uint64 now = curtime();
    uint64 flow_total;
    advertising_policy_t *ads_policy = NULL;
    BOOL need_stopping = FALSE;
    
    if (ntohs(ethh->h_proto) != ETH_P_IP)
        return 0;
    
    spinlock_lock(&auth->lock);
    ++auth->stats.uplink_pkts;
    auth->stats.uplink_bytes += ntohs(iph->tot_len) - (iph->ihl * 4);
    auth->time.latest = now;
    flow_total = auth->stats.uplink_bytes + auth->stats.downlink_bytes;
    switch (auth->acct.status)
    {
    case ACCT_STATUS_ACCTOUNTING:
        if (((ACCT_POLICY_BY_TIME & auth->acct.policy)
                && ((now - auth->time.start) >= auth->acct.valid_time))
            || ((ACCT_POLICY_BY_FLOW & auth->acct.policy)
                && (flow_total >= auth->acct.valid_flow)))
        {
            need_stopping = TRUE;
        }
        break;
    case ACCT_STATUS_NONE:
        break;
    default:
        ++auth->stats.uplink_dropped;
        goto out;
    }

    if (TRUE == is_http(skb))
    {
        ads_policy = advertising_policy_get(auth->ads_push.type);
        if (NULL != ads_policy)
        {
            if (((ADS_POLICY_TIME_INTERVAL & auth->ads_push.policy) 
                    && ((now - auth->ads_push.latest_time) >= ads_policy->time_interval))
                || ((ADS_POLICY_FLOW_INTERVAL & auth->ads_push.policy) 
                    && ((flow_total - auth->ads_push.latest_flow) >= ads_policy->flow_interval)))
            {
                struct tcphdr *tcph = (struct tcphdr *)((int8 *)iph + (iph->ihl*4));
                int8 *body = (int8 *)tcph + tcph->doff * 4;
                if (tcph->psh && tcph->ack && is_http_get_request(body))
                {
                    ret = advertising_redirect(skb, &auth->ads_push.adsid, auth->ads_push.type);
                    if (likely(0 == ret))
                    {
                        auth->ads_push.latest_time = now;
                        auth->ads_push.latest_flow = auth->stats.uplink_bytes + auth->stats.downlink_bytes;
                        ret = -1; /*drop this packet*/
                        goto out;
                    }
                    else
                        DB_WAR("advertising_redirect() fail.");
                }
            }
        }
    }
    ret = 0;
out:
    spinlock_unlock(&auth->lock);
    /*keepalive*/
    spinlock_lock(&s_spinlock_list_auth);
    list_move_tail(&auth->list, &s_list_auth);
    spinlock_unlock(&s_spinlock_list_auth);
    if (unlikely(TRUE == need_stopping))
    {/*
        DB_INF("policy[%d], now[%llu], starttime[%llu], validtime[%llu], totalflow[%llu], validflow[%llu].",
            auth->acct.policy, now, auth->time.start, auth->acct.valid_time, flow_total, auth->acct.valid_flow);*/
        config_authenticated_timeout(auth->mac); /*notify AAA-Client delete timeout user.*/
        authenticated_del(auth);
    }
    return ret;
}

int32 authenticated_downlink_skb_update(authenticated_t *auth,
                                        struct sk_buff *skb)
{
    int32 ret = -1;
    struct iphdr *iph = ip_hdr(skb);
    uint64 now = curtime();
    uint64 flow_total;
    BOOL need_stopping = FALSE;
        
    spinlock_lock(&auth->lock);
    ++auth->stats.downlink_pkts;
    auth->stats.downlink_bytes += ntohs(iph->tot_len) - (iph->ihl * 4);
    auth->time.latest = now;
    flow_total = auth->stats.uplink_bytes + auth->stats.downlink_bytes;
    switch (auth->acct.status)
    {
    case ACCT_STATUS_ACCTOUNTING:
        if (((ACCT_POLICY_BY_TIME & auth->acct.policy)
                && ((now - auth->time.start) >= auth->acct.valid_time))
            || ((ACCT_POLICY_BY_FLOW & auth->acct.policy)
                && (flow_total >= auth->acct.valid_flow)))
        {
            need_stopping = TRUE;
        }
        break;
    case ACCT_STATUS_NONE:
        break;
    default:
        ++auth->stats.downlink_dropped;
        goto out;
    }
    /*TODO: embed advertising*/
    ret = 0;
out:
    spinlock_unlock(&auth->lock);
    /*keepalive*/
    spinlock_lock(&s_spinlock_list_auth);
    list_move_tail(&auth->list, &s_list_auth);
    spinlock_unlock(&s_spinlock_list_auth);
    if (unlikely(TRUE == need_stopping))
    {/*
        DB_INF("policy[%d], now[%llu], starttime[%llu], validtime[%llu], totalflow[%llu], validflow[%llu].",
            auth->acct.policy, now, auth->time.start, auth->acct.valid_time, flow_total, auth->acct.valid_flow);*/
        config_authenticated_timeout(auth->mac); /*notify AAA-Client delete timeout user.*/
        authenticated_del(auth);
    }
    return ret;
}


static struct proc_dir_entry *sp_proc_authenticated = NULL;
#define PROC_AUTHENTICATED  "authenticated"

static ssize_t authenticated_proc_read(struct file *file, 
                                       int8 __user *buf, 
                                       size_t size, 
                                       loff_t *ppos)
{
    int8 tmp[512];
    int32 len;
    int32 copyed = 0;
    authenticated_t *auth = NULL;
    struct list_head *head = (struct list_head *)file->private_data;
    if (unlikely(&s_list_auth == head))
    {
        len = sprintf(tmp, "USER Authenticated Information.\nmax:%u, count:%u\n", 
                    s_maxcount, s_count);
        len += sprintf(tmp+len, "%-18s%-18s%-8s%-8s"
                    "%-8s%-8s%-8s%-8s"
                    "%-8s%-8s%-8s%-8s%-8s%-8s"
                    "%-8s%-8s%-8s"
                    "%-8s%-8s%-8s\n", 
                    "mac", "ipaddr", "stime", "ltime", 
                    "acct", "policy", "times", "flows", 
                    "u-pkts", "d-pkts", "u-bytes", "d-bytes", "u-drop", "d-drop",
                    "push", "p-times", "p-flows", 
                    "embed", "e-times", "e-flows");
        if (likely(len > *ppos))
        {
            len = ((len - *ppos) > size) ? size : len;
            copy_to_user(buf+copyed, tmp+*ppos, len);
            copyed += len;
        }
    }
    while (likely(copyed < size))
    {
        if (unlikely(head->next == &s_list_auth))
            break;
        auth = list_first_entry(head, authenticated_t, list);
        len = sprintf(tmp, MACSTR"  "IPSTR"  %llu  %llu"
            "  %s  %d  %llu  %llu"
            "  %llu  %llu"
            "  %llu  %llu"
            "  %llu  %llu"
            "  %d  %llu  %llu"
            "  %d  %llu  %llu\n", 
            MAC2STR(auth->mac), IP2STR(auth->ipaddr), auth->time.start, auth->time.latest,
            auth->acct.status ? "acct" : "none", auth->acct.policy, auth->acct.valid_time, auth->acct.valid_flow,
            auth->stats.uplink_pkts, auth->stats.downlink_pkts, 
            auth->stats.uplink_bytes, auth->stats.downlink_bytes, 
            auth->stats.uplink_dropped, auth->stats.downlink_dropped,
            auth->ads_push.policy, auth->ads_push.latest_time, auth->ads_push.latest_flow,
            auth->ads_embed.policy, auth->ads_embed.latest_time, auth->ads_embed.latest_flow);
        if (unlikely((len + copyed) > size))
            break;
        copy_to_user(buf+copyed, tmp, len);
        copyed += len;
        head = &auth->list;
        file->private_data = (void *)&auth->list;
    }
    *ppos += copyed;
    return copyed;
}

static int32 authenticated_proc_open(struct inode *inode, 
                                     struct file *file)
{
    file->private_data = (void *)&s_list_auth;
    spinlock_lock(&s_spinlock_list_auth);
    return 0;
}

static int32 authenticated_proc_close(struct inode *inode, 
                                      struct file *file)
{
    spinlock_unlock(&s_spinlock_list_auth);
    file->private_data = NULL;
    return 0;
}

static struct file_operations s_authenticated_fileops = {
    .owner      = THIS_MODULE,
    .read       = authenticated_proc_read,
    .open       = authenticated_proc_open,
    .release    = authenticated_proc_close
};

int32 authenticated_proc_init(struct proc_dir_entry *parent)
{
#ifdef KERNEL_4_4_7
    struct proc_dir_entry *entry = proc_create(PROC_AUTHENTICATED, 0, parent, &s_authenticated_fileops);
#elif defined KERNEL_3_2_88
    struct proc_dir_entry *entry = create_proc_entry(PROC_AUTHENTICATED, 0, parent);
#else
    #error "undefined kernel version"
#endif
    if (NULL == entry)
    {
        DB_ERR("proc_mkdir(%s) fail!!", PROC_AUTHENTICATED);
        return -1;
    }
    sp_proc_authenticated = entry;
    return 0;
}

void authenticated_proc_destroy(struct proc_dir_entry *parent)
{
    remove_proc_entry(PROC_AUTHENTICATED, parent);
}
