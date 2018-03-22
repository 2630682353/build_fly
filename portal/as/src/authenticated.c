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
#include "vlan.h"

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
/*以auth->time.start按从小到大的顺序排序*/
static LIST_HEAD(s_list_auth);
/*以auth->time.latest按从小到大的顺序排序*/
static LIST_HEAD(s_list_auth_keepalive);
static spinlock_t s_spinlock_list_auth_keepalive;

#define DEFAULT_AUTH_MAX_COUNT  (1024)
static uint32 s_count = 0;
static uint32 s_maxcount = DEFAULT_AUTH_MAX_COUNT;
struct task_struct *sp_kthd_auth = NULL;

#define AUTH_HASH_SLOT_MAXCOUNT (64)

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
    return hash % AUTH_HASH_SLOT_MAXCOUNT;
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
    uint64 now = curtime();
    if (unlikely(NULL == dst || NULL == src))
        return -1;
    *dst = memcache_alloc(sp_cache_data);
    bzero(*dst, sp_cache_data->bsize);
    auth = (authenticated_t *)*dst;
    auth2 = (authenticated_t *)src;
    atomic_set(&auth->refcnt, 1);
    auth->time.start = auth->time.latest = now;
    memcpy(auth->mac, auth2->mac, sizeof(auth->mac));
    auth->ipaddr = auth2->ipaddr;
    memcpy(&auth->acct, &auth2->acct, sizeof(auth->acct));
    /*advertising*/
    auth->ads_push.adsid = 0;
    auth->ads_push.latest_flow = 0;
    auth->ads_push.latest_time = now;
    auth->ads_embed.adsid = 0;
    auth->ads_embed.latest_flow = 0;
    auth->ads_embed.latest_time = now;
    
    spinlock_init(&auth->lock); 
    list_add_tail(&auth->list, &s_list_auth);
    
    spinlock_lock(&s_spinlock_list_auth_keepalive);
    list_add_tail(&auth->list_keepalive, &s_list_auth_keepalive);
    spinlock_unlock(&s_spinlock_list_auth_keepalive);
    
    ++s_count;
    return 0;
}

static void authenticated_datafree(void *data)
{
    authenticated_t *auth = (authenticated_t *)data;
    
    spinlock_lock(&s_spinlock_list_auth_keepalive);
    list_del(&auth->list_keepalive);
    spinlock_unlock(&s_spinlock_list_auth_keepalive);
    
    list_del(&auth->list); 
    --s_count;
    spinlock_destroy(&auth->lock);
    bzero(auth, sizeof(*auth));
    memcache_free(sp_cache_data, auth);
}

#define AUTHENTICATED_BURNED_TIME_MAX       /*(10*60)*/(5*24*60*60)
#define AUTHENTICATED_KEEPALIVE_TIME_MAX    /*(60)*/(30*60)
#define AUTHENTICATED_KTHREAD_SLEEP_MSECS   (10*1000)

static int32 authenticated_burned_check_func(void *data)
{
    authenticated_t *auth = NULL;
    BOOL should_sleep = TRUE;
    uint64 now;
    while (!kthread_should_stop())
    {
        should_sleep = TRUE;
        now = curtime();
        /*burned timeout check*/
        rwlock_rdlock(&s_rwlock_htab_auth);
        if (likely(!list_empty(&s_list_auth)))
        {
            list_for_each_entry(auth, &s_list_auth, list)
            {
                if ((now - auth->time.start) >= AUTHENTICATED_BURNED_TIME_MAX)
                {
                    should_sleep = FALSE;
                    break;
                }
            }
            auth = (NULL == auth || &s_list_auth == &auth->list) ? NULL : auth;
        }
        else
            auth = NULL;
        rwlock_rdunlock(&s_rwlock_htab_auth);
        if (NULL != auth)
            authenticated_del(auth);
        
        /*keepalive timeout check*/
        spinlock_lock(&s_spinlock_list_auth_keepalive);
        if (likely(!list_empty(&s_list_auth_keepalive)))
        {
            list_for_each_entry(auth, &s_list_auth_keepalive, list_keepalive)
            {
                if ((now - auth->time.latest) >= AUTHENTICATED_KEEPALIVE_TIME_MAX)
                {
                    should_sleep = FALSE;
                    break;
                }
            }
            auth = (NULL == auth || &s_list_auth_keepalive == &auth->list_keepalive) ? NULL : auth;
        }
        else
            auth = NULL;
        spinlock_unlock(&s_spinlock_list_auth_keepalive);
        if (NULL != auth)
            authenticated_del(auth);

        if (TRUE == should_sleep)
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
    sp_htab_auth = hashtab_create(&ops, AUTH_HASH_SLOT_MAXCOUNT, maxcount);
    if (unlikely(NULL == sp_htab_auth))
    {
        DB_ERR("hashtab_create() call fail.");
        return -1;
    }
    rwlock_init(&s_rwlock_htab_auth);
    
    sp_cache_key = memcache_create(HWADDR_SIZE, maxcount);
    if (unlikely(NULL == sp_cache_key))
    {
        DB_ERR("memcache_create() call fail for cache-key.");
        rwlock_destroy(&s_rwlock_htab_auth);
        hashtab_destroy(sp_htab_auth);
        sp_htab_auth = NULL;
        return -1;
    }
    
    sp_cache_data = memcache_create(sizeof(authenticated_t), maxcount);
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

    spinlock_init(&s_spinlock_list_auth_keepalive);
    
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
        spinlock_destroy(&s_spinlock_list_auth_keepalive);
        return -1;
    }
    return 0;
}

void authenticated_destroy(void)
{
    kthread_stop(sp_kthd_auth);
    
    rwlock_wrlock_bh(&s_rwlock_htab_auth);
    hashtab_destroy(sp_htab_auth);
    sp_htab_auth = NULL;
    s_maxcount = DEFAULT_AUTH_MAX_COUNT;
    s_count = 0;
    INIT_LIST_HEAD(&s_list_auth);
    rwlock_wrunlock_bh(&s_rwlock_htab_auth);
    rwlock_destroy(&s_rwlock_htab_auth);

    memcache_destroy(sp_cache_key);
    sp_cache_key = NULL;

    memcache_destroy(sp_cache_data);
    sp_cache_data = NULL;
  
    spinlock_lock_bh(&s_spinlock_list_auth_keepalive);
    INIT_LIST_HEAD(&s_list_auth_keepalive);
    spinlock_unlock_bh(&s_spinlock_list_auth_keepalive);
    spinlock_destroy(&s_spinlock_list_auth_keepalive);
}

int32 authenticated_add(authenticated_t *auth)
{
    int32 ret = -1;
    if (unlikely(NULL == auth))
    {
        LOGGING_ERR("Attempt to add invalid authentication user information to the users table.");
        return -1;
    }
    rwlock_wrlock_bh(&s_rwlock_htab_auth);
    if (unlikely(s_count >= s_maxcount))
    {
        authenticated_t *auth2;
        auth2 = list_first_entry(&s_list_auth, authenticated_t, list);
        hashtab_delete(sp_htab_auth, auth2->mac);
    }
    ret = hashtab_insert(sp_htab_auth, auth->mac, auth);
    if (unlikely(0 != ret))
    {
        rwlock_wrunlock_bh(&s_rwlock_htab_auth);
        DB_ERR("hashtab_insert() call fail.");
        LOGGING_ERR("Add authentication user to the user's table fail. "
                "mac["MACSTR"], acct_status:%d, acct_policy:%d, "
                "total_seconds:%llu, total_flows:%llu",
                MAC2STR(auth->mac), auth->acct.status, auth->acct.policy, 
                auth->acct.valid_time, auth->acct.valid_flow);
        return -1;
    }
    rwlock_wrunlock_bh(&s_rwlock_htab_auth);
    LOGGING_INFO("Add authentication user to the user's table successfully. "
            "mac["MACSTR"], acct_status:%d, acct_policy:%d, "
            "total_seconds:%llu, total_flows:%llu",
            MAC2STR(auth->mac), auth->acct.status, auth->acct.policy, 
            auth->acct.valid_time, auth->acct.valid_flow);
    return 0;
}

/*本接口是提供给AAA-Client调用删除auth用的*/
void authenticated_del_bh(const void *mac)
{
    authenticated_t *auth;
    rwlock_wrlock_bh(&s_rwlock_htab_auth);
    auth = (authenticated_t *)hashtab_search(sp_htab_auth, mac);
    if (NULL != auth && atomic_dec_and_test(&auth->refcnt))
        hashtab_delete(sp_htab_auth, auth->mac);
    rwlock_wrunlock_bh(&s_rwlock_htab_auth);
    LOGGING_INFO("Successful remove the user from the authenticated user list. mac["MACSTR"].", MAC2STR(mac));
}

void authenticated_del(authenticated_t *auth)
{
    if (unlikely(NULL == auth))
        return;
    if (likely(atomic_read(&auth->refcnt) == 1))
        smp_rmb();
    else if (likely(!atomic_dec_and_test(&auth->refcnt)))
        return;
    LOGGING_INFO("Successful remove the user from the authenticated user list. mac["MACSTR"].", MAC2STR(auth->mac));
    config_authenticated_timeout(auth->mac); /*通知应用层删除指定认证通过的用户*/
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
    struct iphdr *iph = NULL;
    uint64 now = curtime();
    uint64 flow_total;
    advertising_policy_t *ads_policy = NULL;
    BOOL need_stopping = FALSE;
    
    if (skb_from_vlan_dev(skb))
    {
        struct vlan_ethhdr *vethh = vlan_eth_hdr(skb);
        if (htons(ETH_P_IP) != vethh->h_vlan_encapsulated_proto)
            return 0;
        else
            iph = http_iphdr(skb);
    }
    else
    {
        struct ethhdr *ethh = eth_hdr(skb);
        if (htons(ETH_P_IP) != ethh->h_proto)
            return 0;
        else
            iph = http_iphdr(skb);
    }
    
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
        spinlock_unlock(&auth->lock);
        break;
    case ACCT_STATUS_NONE:
        spinlock_unlock(&auth->lock);
        break;
    default:
        ++auth->stats.uplink_dropped;
        spinlock_unlock(&auth->lock);
        goto out;
    }

    if (TRUE == is_http(skb))
    {
        ads_policy = advertising_policy_get(ADS_TYPE_PUSH);
        if (NULL != ads_policy)
        {
            uint64 latest_time;
            uint64 latest_flow;
            uint32 adsid;
            spinlock_lock(&auth->lock);
            latest_time = auth->ads_push.latest_time;
            latest_flow = auth->ads_push.latest_flow;
            adsid = auth->ads_push.adsid;
            spinlock_unlock(&auth->lock);
            
            if (((ADS_POLICY_TIME_INTERVAL & ads_policy->policy) 
                    && ((now - latest_time) >= ads_policy->time_interval))
                || ((ADS_POLICY_FLOW_INTERVAL & ads_policy->policy) 
                    && ((flow_total - latest_flow) >= ads_policy->flow_interval)))
            {
                struct tcphdr *tcph = (struct tcphdr *)((int8 *)iph + (iph->ihl*4));
                int8 *body = (int8 *)tcph + tcph->doff * 4;
                uint32 tcp_dlen = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
                if (tcph->psh && tcph->ack && (tcp_dlen > 0) && is_http_get_request(body))
                {
                    /*因为advertising_redirect中存在对skb的分配,可能存在阻塞。
                     *所以本函数执行不能再spinlock中执行。*/
                    ret = advertising_redirect(skb, &adsid, ADS_TYPE_PUSH);
                    if (likely(0 == ret))
                    {
                        spinlock_lock(&auth->lock);
                        auth->ads_push.adsid = adsid;
                        auth->ads_push.latest_time = now;
                        auth->ads_push.latest_flow = flow_total;
                        ret = -1; /*drop this packet*/
                        spinlock_unlock(&auth->lock);
                        goto out;
                    }
                    else
                    {
                        spinlock_lock(&auth->lock);
                        auth->ads_push.latest_time = now;
                        auth->ads_push.latest_flow = flow_total;
                        spinlock_unlock(&auth->lock);
                        DB_WAR("advertising_redirect() fail.");
                    }
                }
            }
        }
    }
    
    ret = 0;
out:
    /*keepalive*/
    spinlock_lock(&s_spinlock_list_auth_keepalive);
    list_move_tail(&auth->list_keepalive, &s_list_auth_keepalive);
    spinlock_unlock(&s_spinlock_list_auth_keepalive);
    if (unlikely(TRUE == need_stopping))
    {
        DB_INF("authenticated user need stopping now. hwaddr["MACSTR"].", MAC2STR(auth->mac));
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
        spinlock_unlock(&auth->lock);
        break;
    case ACCT_STATUS_NONE:
        spinlock_unlock(&auth->lock);
        break;
    default:
        ++auth->stats.downlink_dropped;
        spinlock_unlock(&auth->lock);
        goto out;
    }
    /*TODO: embed advertising*/
    ret = 0;
out:
    /*keepalive*/
    spinlock_lock(&s_spinlock_list_auth_keepalive);
    list_move_tail(&auth->list_keepalive, &s_list_auth_keepalive);
    spinlock_unlock(&s_spinlock_list_auth_keepalive);
    if (unlikely(TRUE == need_stopping))
    {
        DB_INF("authenticated user need stopping now. hwaddr["MACSTR"].", MAC2STR(auth->mac));
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
        len += sprintf(tmp+len, "%s  %s  %s  %s  "
                    "%s  %s  %s  %s  "
                    "%s  %s  "
                    "%s  %s  "
                    "%s  %s  "
                    "%s  %s  "
                    "%s  %s\n", 
                    "mac", "ipaddr", "stime", "ltime", 
                    "acct", "policy", "times", "flows", 
                    "uplink-pkts", "downlink-pkts", 
                    "uplink-bytes", "downlink-bytes", 
                    "uplink-drop", "downlink-drop",
                    "push-times", "push-flows", 
                    "embed-times", "embed-flows");
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
        spinlock_lock_bh(&auth->lock);
        len = sprintf(tmp, MACSTR"  "IPSTR"  %llu  %llu"
            "  %s  %d  %llu  %llu"
            "  %llu  %llu"
            "  %llu  %llu"
            "  %llu  %llu"
            "  %llu  %llu"
            "  %llu  %llu\n", 
            MAC2STR(auth->mac), IP2STR(auth->ipaddr), auth->time.start, auth->time.latest,
            auth->acct.status ? "acct" : "none", auth->acct.policy, auth->acct.valid_time, auth->acct.valid_flow,
            auth->stats.uplink_pkts, auth->stats.downlink_pkts, 
            auth->stats.uplink_bytes, auth->stats.downlink_bytes, 
            auth->stats.uplink_dropped, auth->stats.downlink_dropped,
            auth->ads_push.latest_time, auth->ads_push.latest_flow,
            auth->ads_embed.latest_time, auth->ads_embed.latest_flow);
        spinlock_unlock_bh(&auth->lock);
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
    authenticated_t *auth;
    /*在此处先将所有的auth用户的引用+1,避免在read过程中出现auth被删除,从而造成指针访问出错*/
    rwlock_rdlock_bh(&s_rwlock_htab_auth);
    list_for_each_entry(auth, &s_list_auth, list)
        authenticated_get(auth);
    rwlock_rdunlock_bh(&s_rwlock_htab_auth);
    file->private_data = &s_list_auth;
    return 0;
}

static int32 authenticated_proc_close(struct inode *inode, 
                                      struct file *file)
{
    authenticated_t *auth, *auth_next;
    /*为了保证指针的安全,此处必须使用list_for_each_entry_safe*/
    list_for_each_entry_safe(auth, auth_next, &s_list_auth, list)
        authenticated_del_bh(auth->mac);
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
    struct proc_dir_entry *entry = proc_create(PROC_AUTHENTICATED, 0, parent, &s_authenticated_fileops);
    if (NULL == entry)
    {
        DB_ERR("proc_create(%s) fail!!", PROC_AUTHENTICATED);
        return -1;
    }
    sp_proc_authenticated = entry;
    return 0;
}

void authenticated_proc_destroy(struct proc_dir_entry *parent)
{
    remove_proc_entry(PROC_AUTHENTICATED, parent);
}
