#ifndef __AUTHENTICATED_H__
#define __AUTHENTICATED_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/proc_fs.h>
#include "type.h"
#include "def.h"
#include "spinlock.h"

/*accounting status*/
typedef enum acct_status_en{
    ACCT_STATUS_NONE        = 0x00,
    ACCT_STATUS_ACCTOUNTING = 0x01
}acct_status_e;
static inline int8 *acct_status_to_str(const int8 status)
{
    if (ACCT_STATUS_NONE == status)
        return "NONE";
    else
        return "ACCT";
}
/*accounting policy*/
typedef enum acct_policy_en{
    ACCT_POLICY_BY_TIME = 0x01,
    ACCT_POLICY_BY_FLOW = 0x02
}acct_policy_e;
static inline int8 *acct_policy_to_str(const int8 policy)
{
    if ((ACCT_POLICY_BY_TIME | ACCT_POLICY_BY_FLOW) == policy)
        return "TIME-FLOW";
    else if (ACCT_POLICY_BY_TIME == policy)
        return "TIME";
    else if (ACCT_POLICY_BY_FLOW == policy)
        return "FLOW";
    else
        return "UNKNOWN";
}

typedef struct auth_acct_st{
    int8 status;        /*Values from enum "acct_status_e"*/
    int8 policy;        /*Values from enum "acct_policy_e"*/
    int8 reserve[2];
    uint64 valid_time;  /*Package valid time*/
    uint64 valid_flow;  /*Package valid flow*/
}auth_acct_t;

typedef struct auth_flow_stats_st{
    uint64 uplink_pkts;         /*number of uplink packets*/
    uint64 downlink_pkts;       /*number of downlink packets*/
    uint64 uplink_bytes;        /*number of uplink bytes*/
    uint64 downlink_bytes;      /*number of downlink bytes*/
    uint64 uplink_dropped;      /*number of uplink dropped packets*/
    uint64 downlink_dropped;    /*number of downlink dropped packets*/
}auth_flow_stats_t;

typedef struct auth_ads_st{
    uint32 adsid;    /*A recent visit to the advertising ID*/
    uint64 latest_time;
    uint64 latest_flow;
}auth_ads_t;

typedef struct authenticated_st{
    struct list_head list;
    struct list_head list_keepalive;
    atomic_t refcnt;
    spinlock_t lock;
    uint8 mac[HWADDR_SIZE];
    uint32 ipaddr;
    int8 reserve;
    struct {
        uint64 start;
        uint64 latest;
    } time;
    auth_acct_t acct;
    auth_flow_stats_t stats;
    auth_ads_t ads_push;
    auth_ads_t ads_embed;
}authenticated_t;

int32 authenticated_init(const uint32 maxcount);
void authenticated_destroy(void);
int32 authenticated_add(authenticated_t *auth);
void authenticated_del_by_mac(const void *mac);
void authenticated_del(authenticated_t *auth);
authenticated_t *authenticated_get(authenticated_t *auth);
void authenticated_put(authenticated_t *auth);
authenticated_t *authenticated_search(const void *mac);
int32 authenticated_uplink_skb_check(struct sk_buff *skb);
int32 authenticated_downlink_skb_check(struct sk_buff *skb);
int32 authenticated_proc_init(struct proc_dir_entry *parent);
void authenticated_proc_destroy(struct proc_dir_entry *parent);

#ifdef  __cplusplus
}
#endif

#endif /*__AUTHENTICATED_H__*/
