#ifndef __WHITELIST_H__
#define __WHITELIST_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/proc_fs.h>
#include <linux/list.h>
#include <linux/skbuff.h>

#include "type.h"
#include "def.h"
#include "atomic.h"
#include "spinlock.h"

typedef struct whitelist_flow_stats_st{
    uint64 uplink_pkts;         /*number of uplink packets*/
    uint64 downlink_pkts;       /*number of downlink packets*/
}whitelist_flow_stats_t;

typedef struct whitelist_st{
    struct list_head list;
    atomic_t refcnt;
    uint8 mac[HWADDR_SIZE];
    int8 reserve[2];
    spinlock_t lock;
    whitelist_flow_stats_t stats;
}whitelist_t;

int32 whitelist_init(const uint32 maxcount);
void whitelist_destroy(void);
int32 whitelist_add(whitelist_t *white);
void whitelist_del_by_mac(const void *mac);
void whitelist_del(whitelist_t *white);
whitelist_t *whitelist_get(whitelist_t *white);
void whitelist_put(whitelist_t *white);
whitelist_t *whitelist_search(const void *mac);
int32 whitelist_uplink_skb_check(struct sk_buff *skb);
int32 whitelist_downlink_skb_check(struct sk_buff *skb);
int32 whitelist_proc_init(struct proc_dir_entry *parent);
void whitelist_proc_destroy(struct proc_dir_entry *parent);

#ifdef  __cplusplus
}
#endif

#endif /*__WHITELIST_H__*/

