#ifndef __PORTAL_H__
#define __PORTAL_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/if_vlan.h>
#include <linux/proc_fs.h>
#include <linux/list.h>

#include "type.h"
#include "def.h"
#include "atomic.h"
#include "vlan.h"
#include "debug.h"

typedef struct portal_interface_st{
    struct list_head list;
    atomic_t refcnt;
    int8 ifname[IFNAME_SIZE];
    int8 url[URL_SIZE];
}portal_interface_t;

int32 portal_interface_add(const int8 *ifname,
                           const int8 *url);
void portal_interface_delete(const int8 *ifname);
portal_interface_t *portal_interface_get(const int8 *ifname);
void portal_interface_put(portal_interface_t *interface);
BOOL portal_interface_exist(const int8 *ifname);

typedef struct portal_vlan_st{
    struct list_head list;
    atomic_t refcnt;
    uint16 vlan_id;
    uint16 reserve;
    int8 url[URL_SIZE];
}portal_vlan_t;
int32 portal_vlan_add(const uint16 vlan_id,
                      const int8 *url);
void portal_vlan_delete(const uint16 vlan_id);
portal_vlan_t *portal_vlan_get(const uint16 vlan_id);
void portal_vlan_put(portal_vlan_t *vlan);
BOOL portal_vlan_exist(const uint16 vlan_id);

static inline BOOL portal_skb_exist(const struct sk_buff *skb)
{
    if (likely(TRUE == skb_from_vlan_dev(skb)))
    {
        struct vlan_ethhdr *vethh = vlan_eth_hdr(skb);
        if (likely(TRUE == portal_vlan_exist(ntohs(vethh->h_vlan_TCI))))
            return TRUE;
        else if (TRUE == portal_interface_exist(skb->dev->name))
            return TRUE;
        else
            return FALSE;
    }
    else
    {
        if (likely(TRUE == portal_interface_exist(skb->dev->name)))
            return TRUE;
        else
            return FALSE;
    }
}

int32 portal_init(void);
void portal_destroy(void);

int32 portal_proc_init(struct proc_dir_entry *parent);
void portal_proc_destroy(struct proc_dir_entry *parent);


#ifdef  __cplusplus
}
#endif

#endif /*__PORTAL_H__*/


