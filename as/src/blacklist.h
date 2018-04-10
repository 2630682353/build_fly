#ifndef __BLACKLIST_H__
#define __BLACKLIST_H__

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

typedef struct blacklist_flow_stats_st{
    uint64 uplink_pkts;         /*number of uplink packets*/
    uint64 downlink_pkts;       /*number of downlink packets*/
}blacklist_flow_stats_t;

typedef struct blacklist_st{
    struct list_head list;
    atomic_t refcnt;
    uint8 mac[HWADDR_SIZE];
    int8 reserve[2];
    spinlock_t lock;
    blacklist_flow_stats_t stats;
}blacklist_t;

int32 blacklist_init(const uint32 maxcount);
void blacklist_destroy(void);
int32 blacklist_add(blacklist_t *black);
void blacklist_del_by_mac(const void *mac);
void blacklist_del(blacklist_t *black);
blacklist_t *blacklist_get(blacklist_t *black);
void blacklist_put(blacklist_t *black);
blacklist_t *blacklist_search(const void *mac);
int32 blacklist_uplink_skb_check(struct sk_buff *skb);
int32 blacklist_downlink_skb_check(struct sk_buff *skb,
                                   const uint8 *hw_dest);
int32 blacklist_proc_init(struct proc_dir_entry *parent);
void blacklist_proc_destroy(struct proc_dir_entry *parent);

#ifdef  __cplusplus
}
#endif

#endif /*__BLACKLIST_H__*/
