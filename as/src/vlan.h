#ifndef __VLAN_H__
#define __VLAN_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"
#include <linux/if_vlan.h>

static inline BOOL skb_from_vlan_dev(const struct sk_buff *skb)
{
    if (skb->protocol == htons(ETH_P_8021Q) 
        || skb->protocol == htons(ETH_P_8021AD))
	    return TRUE;
    else
        return FALSE;
}

static inline BOOL skb_to_vlan_dev(const struct sk_buff *skb)
{
    return is_vlan_dev(skb->dev) ? TRUE : FALSE;
}

#ifdef  __cplusplus
}
#endif

#endif /*__VLAN_H__*/

