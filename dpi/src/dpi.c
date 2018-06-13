#include <linux/module.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include "type.h"
#include "memcache.h"
#include "spinlock.h"
#include "rwlock.h"
#include "time.h"
#include "message.h"
#include "debug.h"
#include "dpi-hook.h"
#include "def.h"
#include "klog.h"

enum {
    DPI_POSITION_AUTH_UPLINK    = 0x00,
    DPI_POSITION_AUTH_DOWNLINK  = 0x01,
    DPI_POSITION_BLACK_UPLINK   = 0x02,
    DPI_POSITION_BLACK_DOWNLINK = 0x03,
    DPI_POSITION_WHITE_UPLINK   = 0x04,
    DPI_POSITION_WHITE_DOWNLINK = 0x05,
    
    DPI_POSITION_MAXNUM         = 0x06
};
#define DPI_POSITION_VALID(pos) ((pos)>=DPI_POSITION_AUTH_UPLINK && (pos)<DPI_POSITION_MAXNUM)
static inline int8 *dpi_position_to_str(const int32 position)
{
    switch (position)
    {
        case DPI_POSITION_AUTH_UPLINK:
            return "AUTH-UPLINK";
        case DPI_POSITION_AUTH_DOWNLINK:
            return "AUTH-DOWNLINK";
        case DPI_POSITION_BLACK_UPLINK:
            return "BLACK-UPLINK";
        case DPI_POSITION_BLACK_DOWNLINK:
            return "BLACK-DOWNLINK";
        case DPI_POSITION_WHITE_UPLINK:
            return "WHITE-UPLINK";
        case DPI_POSITION_WHITE_DOWNLINK:
            return "WHITE-DOWNLINK";
        default:
            return "UNDEFINED";
    }
}
enum {
    DPI_L4_PROTO_ALL    = 0x00000000,
    DPI_L4_PROTO_TCP    = 0x00000001,
    DPI_L4_PROTO_UDP    = 0x00000002,
    DPI_L4_PROTO_OTHER  = 0xffffffff
};
static inline int8 *dpi_l4_proto_to_str(const int32 proto)
{
    switch (proto)
    {
        case DPI_L4_PROTO_ALL:
            return "ALL";
        case DPI_L4_PROTO_TCP:
            return "TCP";
        case DPI_L4_PROTO_UDP:
            return "UDP";
        case DPI_L4_PROTO_OTHER:
            return "OTHER";
        default:
            return "UNDEFINED";
    }
}

typedef struct dpi_policy_st{
    int32 position;
    uint64 maxcnt;  /*最多抓取的数据包的个数*/
    uint64 maxsecs; /*最长抓取的数据包的时间(单位:秒)*/
    uint8 intra_mac[HWADDR_SIZE]; /*00:00:00:00:00:00全部; 否则指定mac地址*/
    uint32 intra_ip;
    uint32 intra_mask;
    uint32 outer_ip;
    uint32 outer_mask;
    int32 l4_proto;
    union {
        /*l4_proto == DPI_L4_PROTO_TCP || l4_proto == DPI_L4_PROTO_UDP*/
        struct {
            uint16 outer_port;
        }port;
    };
}dpi_policy_t;

typedef struct policy_info_head_st{
    struct list_head head;
    int32 position;
    uint32 policy_count;
    rwlock_t lock;
}policy_info_head_t;

typedef struct policy_info_st{
    struct list_head list;
    policy_info_head_t *head;
    atomic_t refcnt;
    uint64 start_time;
    uint64 latest_time;
    uint64 grabed_count;
    uint64 lose_count;
    dpi_policy_t policy;
}policy_info_t;
static policy_info_head_t s_policy_info_heads[DPI_POSITION_MAXNUM];

static memcache_t *sp_cache_policy = NULL;
static spinlock_t s_spinlock_cache_policy;
static BOOL s_dpi_base_inited = FALSE;

static inline void policy_info_add_bh(policy_info_head_t *head,
                                      const dpi_policy_t *policy)
{
    policy_info_t *info;
    rwlock_wrlock_bh(&head->lock);
    list_for_each_entry(info, &head->head, list)
    {
        if (0 == memcmp(&info->policy, policy, sizeof(*policy)))
        {
            rwlock_wrunlock_bh(&head->lock);
            return ;/*already exists*/
        }
    }
    spinlock_lock(&s_spinlock_cache_policy);
    info = (policy_info_t *)memcache_alloc(sp_cache_policy);
    spinlock_unlock(&s_spinlock_cache_policy);
    if (NULL == info)
    {
        DB_ERR("memcache_alloc() call failed for policy_info_t alloc.");
        return;
    }
    info->head = head;
    atomic_set(&info->refcnt, 1);
    memcpy(&info->policy, policy, sizeof(*policy));
    info->start_time = info->latest_time = curtime();
    DB_INF("info:%p, info->start_time:%llu, info->latest_time:%llu, curtime:%lu.",
        info, info->start_time, info->latest_time, curtime());
    info->grabed_count = 0;
    info->lose_count = 0;
    list_add_tail(&info->list, &head->head);
    ++head->policy_count;
    rwlock_wrunlock_bh(&head->lock);
    if (DPI_L4_PROTO_TCP == info->policy.l4_proto
        || DPI_L4_PROTO_UDP == info->policy.l4_proto)
        LOGGING_INFO("Successfully adding dpi policy to dpi module. "
                    "position[%s],maxcount[%llu]"
                    ",maxsecs[%llu],intra_mac["MACSTR"]"
                    ",intra_ip["IPSTR"],intra_mask["IPSTR"]"
                    ",outer_ip["IPSTR"],outer_mask["IPSTR"]"
                    ",l4_proto[%s],outer_port[%u].",
                    dpi_position_to_str(info->policy.position), info->policy.maxcnt, 
                    info->policy.maxsecs, MAC2STR(info->policy.intra_mac),
                    IP2STR(htonl(info->policy.intra_ip)), IP2STR(htonl(info->policy.intra_mask)), 
                    IP2STR(htonl(info->policy.outer_ip)), IP2STR(htonl(info->policy.outer_mask)),
                    dpi_l4_proto_to_str(info->policy.l4_proto), info->policy.port.outer_port);
    else
        LOGGING_INFO("Successfully adding dpi policy to dpi module. "
                    "position[%s],maxcount[%llu]"
                    ",maxsecs[%llu],intra_mac["MACSTR"]"
                    ",intra_ip["IPSTR"],intra_mask["IPSTR"]"
                    ",outer_ip["IPSTR"],outer_mask["IPSTR"]"
                    ",l4_proto[%s].",
                    dpi_position_to_str(info->policy.position), info->policy.maxcnt, 
                    info->policy.maxsecs, MAC2STR(info->policy.intra_mac),
                    IP2STR(htonl(info->policy.intra_ip)), IP2STR(htonl(info->policy.intra_mask)), 
                    IP2STR(htonl(info->policy.outer_ip)), IP2STR(htonl(info->policy.outer_mask)),
                    dpi_l4_proto_to_str(info->policy.l4_proto));
}

static inline void policy_info_del_bh(policy_info_head_t *head,
                                      policy_info_t *info)
{
    if (unlikely(NULL == head || NULL == info))
        return;
    if (unlikely(atomic_dec_and_test(&info->refcnt)))
        smp_rmb();
    else
        return;
    if (DPI_L4_PROTO_TCP == info->policy.l4_proto
        || DPI_L4_PROTO_UDP == info->policy.l4_proto)
        LOGGING_INFO("Successfully removing dpi policy from dpi module. "
                    "position[%s],maxcount[%llu]"
                    ",maxsecs[%llu],intra_mac["MACSTR"]"
                    ",intra_ip["IPSTR"],intra_mask["IPSTR"]"
                    ",outer_ip["IPSTR"],outer_mask["IPSTR"]"
                    ",l4_proto[%s],outer_port[%u].",
                    dpi_position_to_str(info->policy.position), info->policy.maxcnt, 
                    info->policy.maxsecs, MAC2STR(info->policy.intra_mac),
                    IP2STR(htonl(info->policy.intra_ip)), IP2STR(htonl(info->policy.intra_mask)), 
                    IP2STR(htonl(info->policy.outer_ip)), IP2STR(htonl(info->policy.outer_mask)),
                    dpi_l4_proto_to_str(info->policy.l4_proto), info->policy.port.outer_port);
    else
        LOGGING_INFO("Successfully removing dpi policy from dpi module. "
                    "position[%s],maxcount[%llu]"
                    ",maxsecs[%llu],intra_mac["MACSTR"]"
                    ",intra_ip["IPSTR"],intra_mask["IPSTR"]"
                    ",outer_ip["IPSTR"],outer_mask["IPSTR"]"
                    ",l4_proto[%s].",
                    dpi_position_to_str(info->policy.position), info->policy.maxcnt, 
                    info->policy.maxsecs, MAC2STR(info->policy.intra_mac),
                    IP2STR(htonl(info->policy.intra_ip)), IP2STR(htonl(info->policy.intra_mask)), 
                    IP2STR(htonl(info->policy.outer_ip)), IP2STR(htonl(info->policy.outer_mask)),
                    dpi_l4_proto_to_str(info->policy.l4_proto));
    rwlock_wrlock_bh(&head->lock);
    list_del(&info->list);
    --head->policy_count;
    spinlock_lock(&s_spinlock_cache_policy);
    memcache_free(sp_cache_policy, info);
    spinlock_unlock(&s_spinlock_cache_policy);
    rwlock_wrunlock_bh(&head->lock);
}

static inline void policy_info_del(policy_info_head_t *head,
                                   policy_info_t *info)
{
    if (unlikely(NULL == head || NULL == info))
        return;
    if (unlikely(atomic_dec_and_test(&info->refcnt)))
        smp_rmb();
    else
        return;
    if (DPI_L4_PROTO_TCP == info->policy.l4_proto
        || DPI_L4_PROTO_UDP == info->policy.l4_proto)
        LOGGING_INFO("Successfully removing dpi policy from dpi module. "
                    "position[%s],maxcount[%llu]"
                    ",maxsecs[%llu],intra_mac["MACSTR"]"
                    ",intra_ip["IPSTR"],intra_mask["IPSTR"]"
                    ",outer_ip["IPSTR"],outer_mask["IPSTR"]"
                    ",l4_proto[%s],outer_port[%u].",
                    dpi_position_to_str(info->policy.position), info->policy.maxcnt, 
                    info->policy.maxsecs, MAC2STR(info->policy.intra_mac),
                    IP2STR(htonl(info->policy.intra_ip)), IP2STR(htonl(info->policy.intra_mask)), 
                    IP2STR(htonl(info->policy.outer_ip)), IP2STR(htonl(info->policy.outer_mask)),
                    dpi_l4_proto_to_str(info->policy.l4_proto), info->policy.port.outer_port);
    else
        LOGGING_INFO("Successfully removing dpi policy from dpi module. "
                    "position[%s],maxcount[%llu]"
                    ",maxsecs[%llu],intra_mac["MACSTR"]"
                    ",intra_ip["IPSTR"],intra_mask["IPSTR"]"
                    ",outer_ip["IPSTR"],outer_mask["IPSTR"]"
                    ",l4_proto[%s].",
                    dpi_position_to_str(info->policy.position), info->policy.maxcnt, 
                    info->policy.maxsecs, MAC2STR(info->policy.intra_mac),
                    IP2STR(htonl(info->policy.intra_ip)), IP2STR(htonl(info->policy.intra_mask)), 
                    IP2STR(htonl(info->policy.outer_ip)), IP2STR(htonl(info->policy.outer_mask)),
                    dpi_l4_proto_to_str(info->policy.l4_proto));
    rwlock_wrlock(&head->lock);
    list_del(&info->list);
    --head->policy_count;
    spinlock_lock(&s_spinlock_cache_policy);
    memcache_free(sp_cache_policy, info);
    spinlock_unlock(&s_spinlock_cache_policy);
    rwlock_wrunlock(&head->lock);
}

static policy_info_t *policy_info_get(policy_info_t *info)
{
    if (likely(NULL != info && atomic_read(&info->refcnt) > 0))
    {
        atomic_inc(&info->refcnt);
        return info;
    }
    else
        return NULL;
}

static inline void policy_info_put(policy_info_t *info)
{
    if (likely(NULL != info))
        policy_info_del(info->head, info);
}

static inline void policy_info_put_bh(policy_info_t *info)
{
    if (likely(NULL != info))
        policy_info_del_bh(info->head, info);
}

static int32 dpi_policy_add_bh(const dpi_policy_t *policy)
{
    if (FALSE == s_dpi_base_inited || NULL == policy 
        || !DPI_POSITION_VALID(policy->position))
        return -1;
    policy_info_add_bh(&s_policy_info_heads[policy->position], policy);
    return 0;
}

static inline void __dpi_policy_del_bh(policy_info_head_t *head,
                                       const dpi_policy_t *policy)
{
    policy_info_t *info, *info_next;
    rwlock_rdlock_bh(&head->lock);
    /*为了保证指针的安全,此处必须使用list_for_each_entry_safe*/
    list_for_each_entry_safe(info, info_next, &head->head, list)
    {
        if (0 == memcmp(&info->policy, policy, sizeof(*policy)))
        {
            rwlock_rdunlock_bh(&head->lock);
            policy_info_del_bh(head, info);
            return;
        }
    }
    rwlock_rdunlock_bh(&head->lock);
}

static void dpi_policy_del_bh(const dpi_policy_t *policy)
{
    if (FALSE == s_dpi_base_inited || NULL == policy 
        || !DPI_POSITION_VALID(policy->position))
        return;
    __dpi_policy_del_bh(&s_policy_info_heads[policy->position], policy);
}

static inline void __dpi_policy_del(policy_info_head_t *head,
                                    const dpi_policy_t *policy)
{
    policy_info_t *info, *info_next;
    rwlock_rdlock(&head->lock);
    /*为了保证指针的安全,此处必须使用list_for_each_entry_safe*/
    list_for_each_entry_safe(info, info_next, &head->head, list)
    {
        if (0 == memcmp(&info->policy, policy, sizeof(*policy)))
        {
            rwlock_rdunlock(&head->lock);
            DB_INF("info:%p, info->refcnt:%d.", info, atomic_read(&info->refcnt));
            policy_info_del(head, info);
            return;
        }
    }
    rwlock_rdunlock(&head->lock);
}

static void dpi_policy_del(const dpi_policy_t *policy)
{
    if (FALSE == s_dpi_base_inited || NULL == policy 
        || !DPI_POSITION_VALID(policy->position))
        return;
    __dpi_policy_del(&s_policy_info_heads[policy->position], policy);
}

static void config_error(void *buf,
                         int32 *size,
                         int8 *fmt, ...)
{
    if (NULL != buf && NULL != size && *size > 0)
    {
        va_list va;
        va_start(va, fmt);
        *size = vsnprintf(buf, *size, fmt, va);
        va_end(va);
    }
}

static int32 config_dpi_policy_add(const int32 cmd,
                                   void *ibuf,
                                   int32 ilen,
                                   void *obuf,
                                   int32 *olen)
{
    dpi_policy_t *policy = (dpi_policy_t *)ibuf;
    int32 ret;
    if (MSG_CMD_DPI_POLICY_ADD != cmd)
    {
        DB_ERR("Invalid cmd. cmd[0x%x],expect-cmd[0x%x].", cmd, MSG_CMD_DPI_POLICY_ADD);
        config_error(obuf, olen, "Invalid cmd. cmd[0x%x],expect-cmd[0x%x].", cmd, MSG_CMD_DPI_POLICY_ADD);
        return ERR_CODE_PARAMETER;
    }
    if (ilen < sizeof(*policy))
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*policy), cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*policy), cmd);
        return ERR_CODE_PARAMETER;
    }
    DB_PARAM("position[%s],maxcount[%llu],"
            "maxsecs[%llu],intra_hwaddr["MACSTR"]"
            ",intra_ip["IPSTR"],intra_mask["IPSTR"]"
            ",outer_ip["IPSTR"],outer_mask["IPSTR"]"
            ",l4_proto[%s],outer_port[%u].",
            dpi_position_to_str(policy->position), policy->maxcnt, 
            policy->maxsecs, MAC2STR(policy->intra_mac),
            IP2STR(htonl(policy->intra_ip)), IP2STR(htonl(policy->intra_mask)),
            IP2STR(htonl(policy->outer_ip)), IP2STR(htonl(policy->outer_mask)),
            dpi_l4_proto_to_str(policy->l4_proto), policy->port.outer_port);
    ret = dpi_policy_add_bh(policy);
    if (0 != ret)
    {
        DB_ERR("dpi_policy_add() fail. cmd[0x%x], errno[%d].", cmd, ret);
        config_error(obuf, olen, "Add dpi policy fail. cmd[0x%x], errno[%d].", cmd, ret);
        return ERR_CODE_OPERATE_ADD;
    }
    *olen = 0;
    return SUCCESS;
}

static int32 config_dpi_policy_del(const int32 cmd,
                                   void *ibuf,
                                   int32 ilen,
                                   void *obuf,
                                   int32 *olen)
{
    dpi_policy_t *policy = (dpi_policy_t *)ibuf;
    if (MSG_CMD_DPI_POLICY_DELETE != cmd)
    {
        DB_ERR("Invalid cmd. cmd[0x%x],expect-cmd[0x%x].", cmd, MSG_CMD_DPI_POLICY_DELETE);
        config_error(obuf, olen, "Invalid cmd. cmd[0x%x],expect-cmd[0x%x].", cmd, MSG_CMD_DPI_POLICY_DELETE);
        return ERR_CODE_PARAMETER;
    }
    if (ilen < sizeof(*policy))
    {
        DB_ERR("Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*policy), cmd);
        config_error(obuf, olen, "Invalid parameter. ibuf[%p],ilen[%d],expect-lenght[%d],cmd[0x%x].", 
                ibuf, ilen, sizeof(*policy), cmd);
        return ERR_CODE_PARAMETER;
    }
    DB_PARAM("position[%s],maxcount[%llu],"
            "maxsecs[%llu],intra_hwaddr["MACSTR"]"
            ",intra_ip["IPSTR"],intra_mask["IPSTR"]"
            ",outer_ip["IPSTR"],outer_mask["IPSTR"]"
            ",l4_proto[%s],outer_port[%u].",
            dpi_position_to_str(policy->position), policy->maxcnt, 
            policy->maxsecs, MAC2STR(policy->intra_mac),
            IP2STR(htonl(policy->intra_ip)), IP2STR(htonl(policy->intra_mask)),
            IP2STR(htonl(policy->outer_ip)), IP2STR(htonl(policy->outer_mask)),
            dpi_l4_proto_to_str(policy->l4_proto), policy->port.outer_port);
    dpi_policy_del_bh(policy);
    *olen = 0;
    return SUCCESS;
}

static struct {
    int32 cmd;
    int32 (*handle)(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen);
} s_dpi_config_handles[] = {
        {MSG_CMD_DPI_POLICY_ADD,          config_dpi_policy_add},
        {MSG_CMD_DPI_POLICY_DELETE,       config_dpi_policy_del}
};


typedef struct dpi_grab_data_st{
    int32 position;
    uint64 timestamp;
    uint8 intra_mac[HWADDR_SIZE];
    int8 reserves[2];
    uint32 intra_ip;
    uint32 outer_ip;
    int32 l4_proto;
    union {
        /*DPI_L4_PROTO_TCP == l4_proto*/
        struct {
            uint16 outer_port;
            uint16 tcp_dlen;
            uint16 grab_dlen;
            uint16 reserved;
        }tcp;
        /*DPI_L4_PROTO_UDP == l4_proto*/
        struct {
            uint16 outer_port;
            uint16 udp_dlen;
            uint16 grab_dlen;
            uint16 reserved;
        }udp;
        /*others L4 proto == l4_proto*/
        struct {
            uint16 ip_dlen;
            uint16 grab_dlen;
        }ip;
    };
} dpi_grab_data_t;

#define DPI_BUFF_SIZE                       (256)
#define DPI_GRABED_BUFF_MAX_SIZE            (DPI_BUFF_SIZE-sizeof(buffer_t))
#define DPI_GRABED_BUFF_DATA_MAX_SIZE       (DPI_GRABED_BUFF_MAX_SIZE-sizeof(dpi_grab_data_t))
#define DPI_GRABED_MAXNUM                   (1024)
static buffer_t *sp_grabed_head = NULL;
static buffer_t *sp_grabed_tail = NULL;
static atomic_t s_grabed_num;
static spinlock_t s_spinlock_grabed;
static memcache_t *sp_cache_grabed = NULL;
static spinlock_t s_spinlock_cache_grabed;

static inline int32 ipproto_to_l4proto(const uint8 ipproto)
{
    switch (ipproto)
    {
        case IPPROTO_TCP:
            return DPI_L4_PROTO_TCP;
        case IPPROTO_UDP:
            return DPI_L4_PROTO_UDP;
        default:
            return DPI_L4_PROTO_OTHER;
    }
}

static inline BOOL policy_mac_all(const policy_info_t *info)
{
    int32 i;
    for (i=0; i<sizeof(info->policy.intra_mac); ++i)
    {
        if (info->policy.intra_mac[i])
            return FALSE;
    }
    return TRUE;
}

static inline buffer_t *grab_buff_alloc(void)
{
    buffer_t *buf;
    spinlock_lock(&s_spinlock_cache_grabed);
    buf = (buffer_t *)memcache_alloc(sp_cache_grabed);
    spinlock_unlock(&s_spinlock_cache_grabed);
    if (NULL == buf)
        return NULL;
    buf->buf = (int8 *)(buf+1);
    buf->size = DPI_GRABED_BUFF_MAX_SIZE;
    buf->offset = 0;
    buf->len = 0;
    buf->next = NULL;
    return buf;
}

static inline void grab_buff_free(buffer_t *buf)
{
    if (NULL == buf)
        return;
    spinlock_lock(&s_spinlock_cache_grabed);
    memcache_free(sp_cache_grabed, buf);
    spinlock_unlock(&s_spinlock_cache_grabed);
}

static inline void grab_buff_free_bh(buffer_t *buf)
{
    if (NULL == buf)
        return;
    spinlock_lock_bh(&s_spinlock_cache_grabed);
    memcache_free(sp_cache_grabed, buf);
    spinlock_unlock_bh(&s_spinlock_cache_grabed);
}

static inline int32 grab_buff_enqueue(buffer_t *buf)
{
    spinlock_lock(&s_spinlock_grabed);
    if (0 == atomic_read(&s_grabed_num))
    {
        ASSERT(NULL == sp_grabed_head && NULL == sp_grabed_tail);
        sp_grabed_head = sp_grabed_tail = buf;
        atomic_set(&s_grabed_num, 1);
    }
    else
    {
        if (atomic_read(&s_grabed_num) >= DPI_GRABED_MAXNUM)
        {
            grab_buff_free(buf);
            spinlock_unlock(&s_spinlock_grabed);
            DB_WAR("s_grabed_num(%u) >= DPI_GRABED_MAXNUM(%u).", 
                atomic_read(&s_grabed_num), DPI_GRABED_MAXNUM);
            LOGGING_WARNING("Cache the number of packages is greater than or equal to the maximum allowed number of package cache. "
                "cache-number[%u],max-cache-number[%u].", atomic_read(&s_grabed_num), DPI_GRABED_MAXNUM);
            return -1;
        }
        sp_grabed_tail->next = buf;
        sp_grabed_tail = buf;
        atomic_inc(&s_grabed_num);
    }
    spinlock_unlock(&s_spinlock_grabed);
    return 0;
}

static inline buffer_t *grab_buff_dequeue(void)
{
    buffer_t *buf = NULL;
    spinlock_lock_bh(&s_spinlock_grabed);
    if (atomic_read(&s_grabed_num))
    {
        buf = sp_grabed_head;
        sp_grabed_head = sp_grabed_head->next;
        if (NULL == sp_grabed_head)
            sp_grabed_tail = NULL;
        atomic_dec(&s_grabed_num);
    }
    spinlock_unlock_bh(&s_spinlock_grabed);
    return buf;
}

static inline uint32 grad_buff_head_length(void)
{
    if (atomic_read(&s_grabed_num))
        return sp_grabed_head->len;
    else
        return 0;
}

static void policy_grab_uplink_skb(const struct sk_buff *skb,
                                   policy_info_t *info)
{
    const struct ethhdr *ethh = eth_hdr(skb);
    const struct iphdr *iph;
    buffer_t *buf = grab_buff_alloc();
    dpi_grab_data_t *grab;
    uint32 real_grab_dlen;
    uint32 i;

    info->latest_time = curtime();
    if (NULL == buf)
    {
        ++info->lose_count;
        return;
    }
    grab = (dpi_grab_data_t *)buf->buf;
    grab->position = info->policy.position;
    grab->timestamp = curtime();//time(NULL);
    memcpy(grab->intra_mac, ethh->h_source, sizeof(grab->intra_mac));
    if (htons(ETH_P_8021Q) == ethh->h_proto 
        || htons(ETH_P_8021AD) == ethh->h_proto)
        iph = (struct iphdr *)(vlan_eth_hdr(skb)+1);
    else
        iph = (struct iphdr *)(ethh+1);
    grab->intra_ip = ntohl(iph->saddr);
    grab->outer_ip = ntohl(iph->daddr);
    grab->l4_proto = ipproto_to_l4proto(iph->protocol);
    switch (grab->l4_proto)
    {
        case DPI_L4_PROTO_TCP:
        {
            struct tcphdr *tcph = (struct tcphdr *)((int8 *)iph + (iph->ihl * 4));
            grab->tcp.outer_port = ntohs(tcph->dest);
            grab->tcp.tcp_dlen = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
            real_grab_dlen = (DPI_GRABED_BUFF_DATA_MAX_SIZE > grab->tcp.tcp_dlen) ? grab->tcp.tcp_dlen : DPI_GRABED_BUFF_DATA_MAX_SIZE;
            /*四字节对齐*/
            grab->tcp.grab_dlen = ALIGN_4_BYTES(real_grab_dlen);
            grab->tcp.reserved = 0;
            memcpy((void *)(grab+1), ((int8 *)tcph + (tcph->doff * 4)), real_grab_dlen);
            for (i=real_grab_dlen; i<grab->tcp.grab_dlen; ++i)
                ((int8 *)(grab+1))[i] = '\0';
            buf->len = sizeof(*grab) + grab->tcp.grab_dlen;
            break;
        }
        case DPI_L4_PROTO_UDP:
        {
            struct udphdr *udph = (struct udphdr *)((int8 *)iph + (iph->ihl * 4));
            uint16 ulen = ntohs(udph->len);
            grab->udp.outer_port = ntohs(udph->dest);
            grab->udp.udp_dlen = ulen - sizeof(*udph);
            real_grab_dlen = (DPI_GRABED_BUFF_DATA_MAX_SIZE > grab->udp.udp_dlen) ? grab->udp.udp_dlen : DPI_GRABED_BUFF_DATA_MAX_SIZE;
            /*四字节对齐*/
            grab->udp.grab_dlen = ALIGN_4_BYTES(real_grab_dlen);
            grab->udp.reserved = 0;
            memcpy((void *)(grab+1), udph+1, real_grab_dlen);
            for (i=real_grab_dlen; i<grab->udp.grab_dlen; ++i)
                ((int8 *)(grab+1))[i] = '\0';
            buf->len = sizeof(*grab) + grab->udp.grab_dlen;
            break;
        }
        case DPI_L4_PROTO_OTHER:
        {
            grab->ip.ip_dlen = ntohs(iph->tot_len) - (iph->ihl * 4);
            real_grab_dlen = (DPI_GRABED_BUFF_DATA_MAX_SIZE > grab->ip.ip_dlen) ? grab->ip.ip_dlen : DPI_GRABED_BUFF_DATA_MAX_SIZE;
            /*四字节对齐*/
            grab->ip.grab_dlen = ALIGN_4_BYTES(real_grab_dlen);
            memcpy((void *)(grab+1), ((int8 *)iph + (iph->ihl * 4)), real_grab_dlen);
            for (i=real_grab_dlen; i<grab->ip.grab_dlen; ++i)
                ((int8 *)(grab+1))[i] = '\0';
            buf->len = sizeof(*grab) + grab->ip.grab_dlen;
            break;
        }
        default:
            ASSERT(0);
            break;
    }
    
    if (0 == grab_buff_enqueue(buf))
        ++info->grabed_count;
    else
        ++info->lose_count;
    /*if TRUE delete policy*/
    if (info->grabed_count >= info->policy.maxcnt 
        || (info->latest_time - info->start_time) >= info->policy.maxsecs)
    {
        policy_info_del(info->head, info);
    }
}

static BOOL policy_l2_match_uplink_skb(const struct sk_buff *skb,
                                       const policy_info_t *info)
{
    if (TRUE == policy_mac_all(info))
        return TRUE;
    else
    {
        const struct ethhdr *ethh = eth_hdr(skb);
        if (0 == memcmp(info->policy.intra_mac, ethh->h_source, sizeof(info->policy.intra_mac)))
            return TRUE;
    }
    return FALSE;
}

static BOOL policy_l3_match_uplink_skb(const struct sk_buff *skb,
                                       const policy_info_t *info)
{
    const struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph;
    if (htons(ETH_P_8021Q) == ethh->h_proto 
        || htons(ETH_P_8021AD) == ethh->h_proto)
    {
        if (htons(ETH_P_IP) != vlan_eth_hdr(skb)->h_vlan_encapsulated_proto)
            return FALSE;
        iph = (struct iphdr *)(vlan_eth_hdr(skb)+1);
    }
    else
    {
        if (htons(ETH_P_IP) != ethh->h_proto)
            return FALSE;
        iph = (struct iphdr *)(ethh+1);
    }
    if (0 == info->policy.intra_ip || 0 == info->policy.intra_mask) /*all intra ip*/
    {
        if (0 == info->policy.outer_ip || 0 == info->policy.outer_mask) /*all outer ip*/
        {
            return TRUE;
        }
        else
        {
            if ((info->policy.outer_ip & info->policy.outer_mask) == (ntohl(iph->daddr) & info->policy.outer_mask))
                return TRUE;
            else
                return FALSE;
        }
    }
    else
    {
        if ((info->policy.intra_ip & info->policy.intra_mask) == (ntohl(iph->saddr) & info->policy.intra_mask))
        {
            if (0 == info->policy.outer_ip || 0 == info->policy.outer_mask) /*all outer ip*/
            {
                return TRUE;
            }
            else
            {
                if ((info->policy.outer_ip & info->policy.outer_mask) == (ntohl(iph->daddr) & info->policy.outer_mask))
                    return TRUE;
                else
                    return FALSE;
            }
        }
        else
            return FALSE;
    }
    return FALSE;
}

static BOOL policy_l4_match_uplink_skb(const struct sk_buff *skb,
                                       const policy_info_t *info)
{
    const struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph;
    if (htons(ETH_P_8021Q) == ethh->h_proto 
        || htons(ETH_P_8021AD) == ethh->h_proto)
        iph = (struct iphdr *)(vlan_eth_hdr(skb)+1);
    else
        iph = (struct iphdr *)(ethh+1);
    if (DPI_L4_PROTO_ALL == info->policy.l4_proto)
        return TRUE;
    if (info->policy.l4_proto != ipproto_to_l4proto(iph->protocol))
        return FALSE;
    else
    {
        switch (info->policy.l4_proto)
        {
            case DPI_L4_PROTO_TCP:
            {
                if (0 == info->policy.port.outer_port) /*all outer port*/
                    return TRUE;
                else
                {
                    struct tcphdr *tcph = (struct tcphdr *)((int8 *)iph + (iph->ihl * 4));
                    if (info->policy.port.outer_port == ntohs(tcph->dest))
                        return TRUE;
                    else
                        return FALSE;
                }
            }
            case DPI_L4_PROTO_UDP:
            {
                if (0 == info->policy.port.outer_port) /*all outer port*/
                    return TRUE;
                else
                {
                    struct udphdr *udph = (struct udphdr *)((int8 *)iph + (iph->ihl * 4));
                    if (info->policy.port.outer_port == ntohs(udph->dest))
                        return TRUE;
                    else
                        return FALSE;
                }
            }
            case DPI_L4_PROTO_OTHER:
                return TRUE;
        }
    }
    return FALSE;
}

static inline BOOL policy_match_uplink_skb(const struct sk_buff *skb,
                                           const policy_info_t *info)
{
    if (FALSE == policy_l2_match_uplink_skb(skb, info))
        return FALSE;
    if (FALSE == policy_l3_match_uplink_skb(skb, info))
        return FALSE;
    if (FALSE == policy_l4_match_uplink_skb(skb, info))
        return FALSE;
    return TRUE;
}

static void policy_grab_downlink_skb(const struct sk_buff *skb,
                                     policy_info_t *info)
{
    const struct ethhdr *ethh = eth_hdr(skb);
    const struct iphdr *iph;
    buffer_t *buf = grab_buff_alloc();
    dpi_grab_data_t *grab;
    
    info->latest_time = curtime();
    if (NULL == buf)
    {
        ++info->lose_count;
        return;
    }
    grab = (dpi_grab_data_t *)buf->buf;
    grab->position = info->policy.position;
    grab->timestamp = curtime();//time(NULL);
    memcpy(grab->intra_mac, ethh->h_dest, sizeof(grab->intra_mac));
    if (htons(ETH_P_8021Q) == ethh->h_proto 
        || htons(ETH_P_8021AD) == ethh->h_proto)
        iph = (struct iphdr *)(vlan_eth_hdr(skb)+1);
    else
        iph = (struct iphdr *)(ethh+1);
    grab->intra_ip = ntohl(iph->daddr);
    grab->outer_ip = ntohl(iph->saddr);
    grab->l4_proto = ipproto_to_l4proto(iph->protocol);
    switch (grab->l4_proto)
    {
        case DPI_L4_PROTO_TCP:
        {
            struct tcphdr *tcph = (struct tcphdr *)((int8 *)iph + (iph->ihl * 4));
            grab->tcp.outer_port = ntohs(tcph->source);
            grab->tcp.tcp_dlen = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
            grab->tcp.grab_dlen = (DPI_GRABED_BUFF_DATA_MAX_SIZE > grab->tcp.tcp_dlen) ? grab->tcp.tcp_dlen : DPI_GRABED_BUFF_DATA_MAX_SIZE;
            grab->tcp.reserved = 0;
            memcpy((void *)(grab+1), ((int8 *)tcph + (tcph->doff * 4)), grab->tcp.grab_dlen);
            buf->len = sizeof(*grab) + grab->tcp.grab_dlen;
            break;
        }
        case DPI_L4_PROTO_UDP:
        {
            struct udphdr *udph = (struct udphdr *)((int8 *)iph + (iph->ihl * 4));
            uint16 ulen = ntohs(udph->len);
            grab->udp.outer_port = ntohs(udph->source);
            grab->udp.udp_dlen = ulen - sizeof(*udph);
            grab->udp.grab_dlen = (DPI_GRABED_BUFF_DATA_MAX_SIZE > grab->udp.udp_dlen) ? grab->udp.udp_dlen : DPI_GRABED_BUFF_DATA_MAX_SIZE;
            grab->udp.reserved = 0;
            memcpy((void *)(grab+1), udph+1, grab->udp.grab_dlen);
            buf->len = sizeof(*grab) + grab->udp.grab_dlen;
            break;
        }
        case DPI_L4_PROTO_OTHER:
        {
            grab->ip.ip_dlen = ntohs(iph->tot_len) - (iph->ihl * 4);
            grab->ip.grab_dlen = (DPI_GRABED_BUFF_DATA_MAX_SIZE > grab->ip.ip_dlen) ? grab->ip.ip_dlen : DPI_GRABED_BUFF_DATA_MAX_SIZE;
            memcpy((void *)(grab+1), ((int8 *)iph + (iph->ihl * 4)), grab->ip.grab_dlen);
            buf->len = sizeof(*grab) + grab->ip.grab_dlen;
            break;
        }
        default:
            ASSERT(0);
            break;
    }
    
    if (0 == grab_buff_enqueue(buf))
        ++info->grabed_count;
    else
        ++info->lose_count;
    /*if TRUE delete policy*/
    if (info->grabed_count >= info->policy.maxcnt 
        || (info->latest_time - info->start_time) >= info->policy.maxsecs)
    {
        policy_info_del(info->head, info);
    }
}

static BOOL policy_l2_match_downlink_skb(const struct sk_buff *skb,
                                         const policy_info_t *info)
{
    if (TRUE == policy_mac_all(info))
        return TRUE;
    else
    {
        const struct ethhdr *ethh = eth_hdr(skb);
        if (0 == memcmp(info->policy.intra_mac, ethh->h_dest, sizeof(info->policy.intra_mac)))
            return TRUE;
    }
    return FALSE;
}

static BOOL policy_l3_match_downlink_skb(const struct sk_buff *skb,
                                         const policy_info_t *info)
{
    const struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph;
    if (htons(ETH_P_8021Q) == ethh->h_proto 
        || htons(ETH_P_8021AD) == ethh->h_proto)
        iph = (struct iphdr *)(vlan_eth_hdr(skb)+1);
    else
        iph = (struct iphdr *)(ethh+1);
    if (0 == info->policy.intra_ip || 0 == info->policy.intra_mask) /*all intra ip*/
    {
        if (0 == info->policy.outer_ip || 0 == info->policy.outer_mask) /*all outer ip*/
        {
            return TRUE;
        }
        else
        {
            if ((info->policy.outer_ip & info->policy.outer_mask) == (ntohl(iph->saddr) & info->policy.outer_mask))
                return TRUE;
            else
                return FALSE;
        }
    }
    else
    {
        if ((info->policy.intra_ip & info->policy.intra_mask) == (ntohl(iph->daddr) & info->policy.intra_mask))
        {
            if (0 == info->policy.outer_ip || 0 == info->policy.outer_mask) /*all outer ip*/
            {
                return TRUE;
            }
            else
            {
                if ((info->policy.outer_ip & info->policy.outer_mask) == (ntohl(iph->saddr) & info->policy.outer_mask))
                    return TRUE;
                else
                    return FALSE;
            }
        }
        else
            return FALSE;
    }
    return FALSE;
}

static BOOL policy_l4_match_downlink_skb(const struct sk_buff *skb,
                                         const policy_info_t *info)
{
    const struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph;
    if (htons(ETH_P_8021Q) == ethh->h_proto 
        || htons(ETH_P_8021AD) == ethh->h_proto)
        iph = (struct iphdr *)(vlan_eth_hdr(skb)+1);
    else
        iph = (struct iphdr *)(ethh+1);
    if (DPI_L4_PROTO_ALL == info->policy.l4_proto)
        return TRUE;
    if (info->policy.l4_proto != ipproto_to_l4proto(iph->protocol))
        return FALSE;
    else
    {
        switch (info->policy.l4_proto)
        {
            case DPI_L4_PROTO_TCP:
            {
                if (0 == info->policy.port.outer_port) /*all outer port*/
                    return TRUE;
                else
                {
                    struct tcphdr *tcph = (struct tcphdr *)((int8 *)iph + (iph->ihl * 4));
                    if (info->policy.port.outer_port == ntohs(tcph->source))
                        return TRUE;
                    else
                        return FALSE;
                }
            }
            case DPI_L4_PROTO_UDP:
            {
                if (0 == info->policy.port.outer_port) /*all outer port*/
                    return TRUE;
                else
                {
                    struct udphdr *udph = (struct udphdr *)((int8 *)iph + (iph->ihl * 4));
                    if (info->policy.port.outer_port == ntohs(udph->source))
                        return TRUE;
                    else
                        return FALSE;
                }
            }
            case DPI_L4_PROTO_OTHER:
                return TRUE;
        }
    }
    return FALSE;
}

static inline BOOL policy_match_downlink_skb(const struct sk_buff *skb,
                                             const policy_info_t *info)
{
    if (FALSE == policy_l2_match_downlink_skb(skb, info))
        return FALSE;
    if (FALSE == policy_l3_match_downlink_skb(skb, info))
        return FALSE;
    if (FALSE == policy_l4_match_downlink_skb(skb, info))
        return FALSE;
    return TRUE;
}

static inline int32 dpi_policy_position_to_direction(const int32 position)
{
    if (DPI_POSITION_AUTH_UPLINK == position
        || DPI_POSITION_BLACK_UPLINK == position
        || DPI_POSITION_WHITE_UPLINK == position)
        return DPI_DIRECTION_UPLINK;
    else
        return DPI_DIRECTION_DOWNLINK;
}

static void dpi_policy_hook_func(struct sk_buff *skb,
                                 void *data)
{
    policy_info_head_t *head = (policy_info_head_t *)data;
    policy_info_t *info, *info_next;
    const struct ethhdr *ethh = eth_hdr(skb);
    const struct iphdr *iph;

    if (FALSE == s_dpi_base_inited)
        return;
    /*只抓取IP数据包,其他类型的数据包直接跳过*/
    if (htons(ETH_P_IP) != ethh->h_proto 
        && htons(ETH_P_8021Q) != ethh->h_proto 
        && htons(ETH_P_8021AD) != ethh->h_proto)
        return;
    else
    {
        if (htons(ETH_P_8021Q) == ethh->h_proto 
            || htons(ETH_P_8021AD) == ethh->h_proto)
        {
            struct vlan_ethhdr *vethh = vlan_eth_hdr(skb);
            if (htons(ETH_P_IP) != vethh->h_vlan_encapsulated_proto)
                return;
            else
                iph = (struct iphdr *)(vethh+1);
        }
        else
            iph = (struct iphdr *)(ethh+1);
    }
    /*匹配规则抓取数据*/
    rwlock_rdlock(&head->lock);
    /*为了保证指针的安全,此处必须使用list_for_each_entry_safe*/
    list_for_each_entry_safe(info, info_next, &head->head, list)
    {
        info = policy_info_get(info);
        if (NULL == info)
            continue;
        rwlock_rdunlock(&head->lock);
        if (DPI_DIRECTION_UPLINK == dpi_policy_position_to_direction(head->position))
        {
            if (TRUE == policy_match_uplink_skb(skb, info))
            {
                policy_grab_uplink_skb(skb, info);
                policy_info_put(info);
                return;
            }
        }
        else
        {
            if (TRUE == policy_match_downlink_skb(skb, info))
            {
                policy_grab_downlink_skb(skb, info);
                policy_info_put(info);
                return;
            }
        }
        policy_info_put(info);
        rwlock_rdlock(&head->lock);
    }
    rwlock_rdunlock(&head->lock);
}

static dpi_hook_ops_t s_dpi_hook_ops[] = {
            {.hook      = dpi_policy_hook_func,
            .priority   = 1,
            .direction  = DPI_DIRECTION_UPLINK,
            .hooknum    = DPI_HOOK_BLACKLIST,
            .data       = (void *)&s_policy_info_heads[DPI_POSITION_BLACK_UPLINK]
            },
            {.hook      = dpi_policy_hook_func,
            .priority   = 1,
            .direction  = DPI_DIRECTION_UPLINK,
            .hooknum    = DPI_HOOK_WHITELIST,
            .data       = (void *)&s_policy_info_heads[DPI_POSITION_WHITE_UPLINK]
            },
            {.hook  = dpi_policy_hook_func,
            .priority   = 1,
            .direction  = DPI_DIRECTION_UPLINK,
            .hooknum    = DPI_HOOK_AUTHENTICATED,
            .data       = (void *)&s_policy_info_heads[DPI_POSITION_AUTH_UPLINK]
            },
            {.hook      = dpi_policy_hook_func,
            .priority   = 1,
            .direction  = DPI_DIRECTION_DOWNLINK,
            .hooknum    = DPI_HOOK_BLACKLIST,
            .data       = (void *)&s_policy_info_heads[DPI_POSITION_BLACK_DOWNLINK]
            },
            {.hook      = dpi_policy_hook_func,
            .priority   = 1,
            .direction  = DPI_DIRECTION_DOWNLINK,
            .hooknum    = DPI_HOOK_WHITELIST,
            .data       = (void *)&s_policy_info_heads[DPI_POSITION_WHITE_DOWNLINK]
            },
            {.hook      = dpi_policy_hook_func,
            .priority   = 1,
            .direction  = DPI_DIRECTION_DOWNLINK,
            .hooknum    = DPI_HOOK_AUTHENTICATED,
            .data       = (void *)&s_policy_info_heads[DPI_POSITION_AUTH_DOWNLINK]
            }
        };


typedef struct dpi_proc_data_st{
    policy_info_head_t *info_head;
    policy_info_t *info;
}dpi_proc_data_t;

static ssize_t dpi_policy_proc_read(struct file *file, 
                                    int8 __user *buf, 
                                    size_t size, 
                                    loff_t *ppos)
{
    int32 copyed = 0;
    int8 tmp[512];
    int32 len;
    dpi_proc_data_t *proc_data = (dpi_proc_data_t *)file->private_data;
    policy_info_t *info;
    struct list_head *head;

    if (NULL == proc_data->info)
    {
        bzero(tmp, sizeof(tmp));
        len = snprintf(tmp, sizeof(tmp), "Position:%s, Policy-count:%u:\n", 
                        dpi_position_to_str(proc_data->info_head->position), 
                        proc_data->info_head->policy_count);
        len += snprintf(tmp+len, sizeof(tmp)-len, "start-time  latest-time"
                        "  grabed-count  lose-count"
                        "  max-count  max-seconds"
                        "  position  intra-hwaddr"
                        "  intra-ip  intra-mask"
                        "  outer-ip  outer-mask"
                        "  l4-proto  outer-port\n");
        if (len > *ppos)
        {
            len = ((len - *ppos) > size) ? size : len;
            copy_to_user(buf+copyed, tmp+*ppos, len);
            copyed += len;
        }
    }
    head = (NULL == proc_data->info) ? &proc_data->info_head->head : &proc_data->info->list;
    while (likely(copyed < size))
    {
        info = list_first_entry(head, policy_info_t, list);
        if (unlikely(&info->list == &proc_data->info_head->head))
            break;
        len = snprintf(tmp, sizeof(tmp), "%llu  %llu"
                        "  %llu  %llu"
                        "  %llu  %llu"
                        "  %s  "MACSTR
                        "  "IPSTR"  "IPSTR
                        "  "IPSTR"  "IPSTR
                        "  %s  %u\n",
                        info->start_time, info->latest_time,
                        info->grabed_count, info->lose_count,
                        info->policy.maxcnt, info->policy.maxsecs,
                        dpi_position_to_str(info->policy.position), MAC2STR(info->policy.intra_mac),
                        IP2STR(htonl(info->policy.intra_ip)), IP2STR(htonl(info->policy.intra_mask)),
                        IP2STR(htonl(info->policy.outer_ip)), IP2STR(htonl(info->policy.outer_mask)),
                        dpi_l4_proto_to_str(info->policy.l4_proto), info->policy.port.outer_port);
        if (unlikely((len + copyed) > size))
            break;
        copy_to_user(buf+copyed, tmp, len);
        copyed += len;
        head = &info->list;
        proc_data->info = info;
    }
    *ppos += copyed;
    return copyed;
}

static int32 dpi_policy_proc_open(struct inode *inode, 
                                  struct file *file)
{
    policy_info_t *info;
    policy_info_head_t *info_head = (policy_info_head_t *)PDE_DATA(inode);
    dpi_proc_data_t *proc_data = (dpi_proc_data_t *)malloc(sizeof(*proc_data));
    proc_data->info_head = info_head;
    proc_data->info = NULL;
    rwlock_rdlock_bh(&info_head->lock);
    list_for_each_entry(info, &info_head->head, list)
    {
        policy_info_get(info);
    }
    rwlock_rdunlock_bh(&info_head->lock);
    file->private_data = (void *)proc_data;
    return 0;
}

static int32 dpi_policy_proc_close(struct inode *inode, 
                                   struct file *file)
{
    dpi_proc_data_t *proc_data = (dpi_proc_data_t *)file->private_data;
    policy_info_t *info, *info_next;
    /*为了保证指针的安全,此处必须使用list_for_each_entry_safe*/
    list_for_each_entry_safe(info, info_next, &proc_data->info_head->head, list)
    {
        policy_info_del_bh(proc_data->info_head, info);
    }
    free(proc_data);
    file->private_data = NULL;
    return 0;
}

static struct file_operations s_dpi_policy_proc_fops = {
        .owner      = THIS_MODULE,
        .read       = dpi_policy_proc_read,
        .open       = dpi_policy_proc_open,
        .release    = dpi_policy_proc_close
    };

static struct {
    int8 *name;
    struct file_operations *fops;
    struct proc_dir_entry *parent;
    struct proc_dir_entry *entry;
    void *data;
} s_dpi_policy_proc[DPI_POSITION_MAXNUM] = {
            {.name = "auth-uplink",
            .fops = &s_dpi_policy_proc_fops,
            .data = (void *)&s_policy_info_heads[DPI_POSITION_AUTH_UPLINK]
            },
            {.name = "auth-downlink",
            .fops = &s_dpi_policy_proc_fops,
            .data = (void *)&s_policy_info_heads[DPI_POSITION_AUTH_DOWNLINK]
            },
            {.name = "black-uplink",
            .fops = &s_dpi_policy_proc_fops,
            .data = (void *)&s_policy_info_heads[DPI_POSITION_BLACK_UPLINK]
            },
            {.name = "black-downlink",
            .fops = &s_dpi_policy_proc_fops,
            .data = (void *)&s_policy_info_heads[DPI_POSITION_BLACK_DOWNLINK]
            },
            {.name = "white-uplink",
            .fops = &s_dpi_policy_proc_fops,
            .data = (void *)&s_policy_info_heads[DPI_POSITION_WHITE_UPLINK]
            },
            {.name = "white-downlink",
            .fops = &s_dpi_policy_proc_fops,
            .data = (void *)&s_policy_info_heads[DPI_POSITION_WHITE_DOWNLINK]
            }
        };

struct proc_dir_entry *sp_dpi_proc = NULL;
#define DPI_PROC    "dpi"
static int32 dpi_proc_init(void)
{
    int32 i = 0;
    struct proc_dir_entry *entry = proc_mkdir(DPI_PROC, NULL);
    if (NULL == entry)
    {
        DB_ERR("proc_mkdir(%s) fail!!", DPI_PROC);
        return -1;
    }
    sp_dpi_proc = entry;
    for (i=0; i<ARRAY_SIZE(s_dpi_policy_proc); ++i)
    {
        entry = proc_create_data(s_dpi_policy_proc[i].name, 0, 
                                sp_dpi_proc, s_dpi_policy_proc[i].fops, 
                                s_dpi_policy_proc[i].data);
        if (NULL == entry)
            goto err;
        s_dpi_policy_proc[i].entry = entry;
        s_dpi_policy_proc[i].parent = sp_dpi_proc;
    }
    return 0;
err:
    while (i > 0)
    {
        --i;
        remove_proc_entry(s_dpi_policy_proc[i].name, s_dpi_policy_proc[i].parent);
        s_dpi_policy_proc[i].parent = NULL;
        s_dpi_policy_proc[i].entry = NULL;
    }
    remove_proc_entry(DPI_PROC, NULL);
    sp_dpi_proc = NULL;
    return -1;
}

static void dpi_proc_destroy(void)
{
    int32 i;
    for (i=0; i<ARRAY_SIZE(s_dpi_policy_proc); ++i)
    {
        remove_proc_entry(s_dpi_policy_proc[i].name, s_dpi_policy_proc[i].parent);
        s_dpi_policy_proc[i].parent = NULL;
        s_dpi_policy_proc[i].entry = NULL;
    }
    remove_proc_entry(DPI_PROC, NULL);
    sp_dpi_proc = NULL;
}

static int32 dpi_base_init(void)
{
    int32 i;
    int32 ret;
    if (TRUE == s_dpi_base_inited)
        return 0;
    
    spinlock_init(&s_spinlock_grabed);
    sp_cache_grabed = memcache_create(DPI_BUFF_SIZE, 16);
    if (NULL == sp_cache_grabed)
    {
        DB_ERR("memcache_create() call fail for dpi grabed data buffer.");
        spinlock_destroy(&s_spinlock_grabed);
        return -1;
    }
    spinlock_init(&s_spinlock_cache_grabed);
    atomic_set(&s_grabed_num, 0);

    sp_cache_policy = memcache_create(sizeof(policy_info_t), 16);
    if (NULL == sp_cache_policy)
    {
        DB_ERR("memcache_create() call fail for dpi policy buffer.");
        spinlock_destroy(&s_spinlock_cache_grabed);
        memcache_destroy(sp_cache_grabed);
        spinlock_destroy(&s_spinlock_grabed);
        return -1;
    }
    spinlock_init(&s_spinlock_cache_policy);
    
    for (i=0; i<ARRAY_SIZE(s_policy_info_heads); ++i)
    {
        INIT_LIST_HEAD(&s_policy_info_heads[i].head);
        s_policy_info_heads[i].position = i;
        rwlock_init(&s_policy_info_heads[i].lock);
    }
    ret = dpi_register_hooks(s_dpi_hook_ops, ARRAY_SIZE(s_dpi_hook_ops));
    if (0 != ret)
    {
        DB_ERR("dpi_register_hooks() call fail. errno[%d].", ret);
        for (i=0; i<ARRAY_SIZE(s_policy_info_heads); ++i)
            rwlock_destroy(&s_policy_info_heads[i].lock);
        spinlock_destroy(&s_spinlock_cache_policy);
        memcache_destroy(sp_cache_policy);
        spinlock_destroy(&s_spinlock_cache_grabed);
        memcache_destroy(sp_cache_grabed);
        spinlock_destroy(&s_spinlock_grabed);
        return -1;
    }

    for (i=0; i<ARRAY_SIZE(s_dpi_config_handles); ++i)
    {
        ret = msg_cmd_register(s_dpi_config_handles[i].cmd, s_dpi_config_handles[i].handle);
        if (0 != ret)
        {
            DB_ERR("msg_cmd_register() fail. cmd[%d], errno[%d].", s_dpi_config_handles[i].cmd, ret);
            while (i > 0)
                msg_cmd_unregister(s_dpi_config_handles[--i].cmd);
            for (i=0; i<ARRAY_SIZE(s_policy_info_heads); ++i)
                rwlock_destroy(&s_policy_info_heads[i].lock);
            spinlock_destroy(&s_spinlock_cache_policy);
            memcache_destroy(sp_cache_policy);
            spinlock_destroy(&s_spinlock_cache_grabed);
            memcache_destroy(sp_cache_grabed);
            spinlock_destroy(&s_spinlock_grabed);
            return -1;
        }
    }
    
    s_dpi_base_inited = TRUE;
    return 0;
}

static void dpi_base_destroy(void)
{
    policy_info_t *info;
    buffer_t *buf;
    int32 i;
    if (FALSE == s_dpi_base_inited)
        return;
    s_dpi_base_inited = FALSE;

    for (i=0; i<ARRAY_SIZE(s_dpi_config_handles); ++i)
        msg_cmd_unregister(s_dpi_config_handles[i].cmd);
    dpi_unregister_hooks(s_dpi_hook_ops, ARRAY_SIZE(s_dpi_hook_ops));
    for (i=0; i<ARRAY_SIZE(s_policy_info_heads); ++i)
    {
        rwlock_wrlock_bh(&s_policy_info_heads[i].lock);
        while (!list_empty(&s_policy_info_heads[i].head))
        {
            info = list_first_entry(&s_policy_info_heads[i].head, policy_info_t, list);
            list_del(&info->list);
            spinlock_lock(&s_spinlock_cache_policy);
            memcache_free(sp_cache_policy, info);
            spinlock_unlock(&s_spinlock_cache_policy);
        }
        rwlock_wrunlock_bh(&s_policy_info_heads[i].lock);
        rwlock_destroy(&s_policy_info_heads[i].lock);
    }
    
    memcache_destroy(sp_cache_policy);
    sp_cache_policy = NULL;
    spinlock_destroy(&s_spinlock_cache_policy);

    while (NULL != (buf = grab_buff_dequeue()))
        grab_buff_free_bh(buf);
    spinlock_destroy(&s_spinlock_grabed);
    memcache_destroy(sp_cache_grabed);
    spinlock_destroy(&s_spinlock_cache_grabed);
}

static int32 dpi_open(struct inode *inode, 
                      struct file *file)
{
    return 0;
}

static int32 dpi_close(struct inode *inode, 
                       struct file *file)
{
    return 0;
}

static ssize_t dpi_read(struct file *file,
	                    int8 __user *buf, 
	                    size_t size, 
	                    loff_t *ppos)
{
    ssize_t copyed = 0;
    buffer_t *tmp;
    uint32 bsize = 0;
    while ((bsize = grad_buff_head_length()) > 0)
    {
        if ((size-copyed) < bsize)
            break;
        tmp = grab_buff_dequeue();
        /* 可能会丢失掉一份已经抓取到的数据 */
        if (NULL == tmp || (size-copyed) < tmp->len)
        {
            grab_buff_free_bh(tmp);
            break;
        }
        copy_to_user(buf+copyed, tmp->buf+tmp->offset, tmp->len);
        copyed += tmp->len;
        grab_buff_free_bh(tmp);
    }
    return copyed;
}

static ssize_t dpi_write(struct file *file,
	                     const int8 __user *buf, 
	                     size_t size, 
	                     loff_t *ppos)
{
    return -EPERM;
}

static uint32 dpi_poll(struct file *file, 
                       poll_table *poll)
{
    uint32 mask = 0;
    if (atomic_read(&s_grabed_num) > 0)
        mask |= POLLIN | POLLRDNORM;
    return mask;
}

static long dpi_ioctl(struct file *file, 
                      uint32 cmd,
                      unsigned long arg)
{
    return -EFAULT;
}

static const struct file_operations s_dpi_fops = {
    .owner          = THIS_MODULE,
    .open           = dpi_open,
    .release        = dpi_close,
    .read           = dpi_read,
    .write          = dpi_write,
    .poll           = dpi_poll,
    .unlocked_ioctl = dpi_ioctl,
};

static struct miscdevice s_dpi_misc_device = {
    .minor  = MISC_DYNAMIC_MINOR,
    .name   = "dpi",
    .fops   = &s_dpi_fops,
};

static int32 dpi_burned_check_kthd_func(void *data)
{
    policy_info_head_t *head;
    policy_info_t *info, *info_next;
    uint32 i;
    BOOL should_sleep = TRUE;
    uint64 now;
    while (!kthread_should_stop())
    {
        should_sleep = TRUE;
        now = curtime();
        for (i=0; i<ARRAY_SIZE(s_policy_info_heads); ++i)
        {
            head = &s_policy_info_heads[i];
            rwlock_rdlock_bh(&head->lock);
            /*为了保证指针的安全,此处必须使用list_for_each_entry_safe*/
            list_for_each_entry_safe(info, info_next, &head->head, list)
            {
                info = policy_info_get(info);
                if (NULL == info)
                    continue;
                rwlock_rdunlock_bh(&head->lock);
                if ((now - info->start_time) >= info->policy.maxsecs)
                {
                    policy_info_del_bh(head, info);
                    should_sleep = FALSE;
                }
                policy_info_put_bh(info);
                rwlock_rdlock_bh(&head->lock);
            }
            rwlock_rdunlock_bh(&head->lock);
        }
        
        if (TRUE == should_sleep)
            msleep_interruptible(10*1000);
    }
    return 0;
}

static struct task_struct *sp_kthd_dpi = NULL;

static int32 __init dpi_module_init(void)
{
    int32 ret;
    ret = misc_register(&s_dpi_misc_device);
    if (0 != ret)
    {
        DB_ERR("DPI Module init fail, register misc_device fail!!");
        return -EIO;
    }
    ret = dpi_base_init();
    if (0 != ret)
    {
        DB_ERR("DPI Module init fail, Init dpi base fail!!");
        misc_deregister(&s_dpi_misc_device);
        return -EIO;
    }
    ret = dpi_proc_init();
    if (0 != ret)
    {
        DB_ERR("DPI Module init fail, Init dpi proc fail!!");
        dpi_base_destroy();
        misc_deregister(&s_dpi_misc_device);
        return -EIO;
    }
    sp_kthd_dpi = kthread_run(dpi_burned_check_kthd_func, NULL, "kthd-dpi");
    if (unlikely(IS_ERR(sp_kthd_dpi)))
    {
        ret = PTR_ERR(sp_kthd_dpi);
        DB_ERR("kthread_run() call fail. errno[%d].", ret);
        sp_kthd_dpi = NULL;
        dpi_proc_destroy();
        dpi_base_destroy();
        misc_deregister(&s_dpi_misc_device);
        return -EIO;
    }
    DB_INF("DPI Module init successfully.");
    return 0;
}

static void __exit dpi_module_exit(void)
{
    if (NULL != sp_kthd_dpi)
        kthread_stop(sp_kthd_dpi);
    dpi_proc_destroy();
    dpi_base_destroy();
    misc_deregister(&s_dpi_misc_device);
    DB_INF("DPI Module remove successfully.");
}

module_init(dpi_module_init);
module_exit(dpi_module_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("zxc");
MODULE_DESCRIPTION("This module is a DPI Module for grabing net packet information.");
