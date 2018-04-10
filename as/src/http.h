#ifndef __HTTP_H__
#define __HTTP_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include "type.h"
#include "def.h"
#include "vlan.h"
#include "debug.h"


static inline struct iphdr *http_iphdr(const struct sk_buff *skb)
{
    if (skb_from_vlan_dev(skb))
        return (struct iphdr *)(vlan_eth_hdr(skb) + 1);
    else
        return (struct iphdr *)(eth_hdr(skb) + 1);
}

static inline BOOL is_http_get_request(int8 *data)
{
	return (0 == memcmp(data, "GET", 3)) ? TRUE : FALSE;
}

static inline BOOL is_http(struct sk_buff *skb)
{
    if (skb_from_vlan_dev(skb))
    {
        struct vlan_ethhdr *vethh = vlan_eth_hdr(skb);
        struct iphdr *iph = http_iphdr(skb);
        
        if (htons(ETH_P_IP) == vethh->h_vlan_encapsulated_proto
            && IPPROTO_TCP == iph->protocol)
        {
            struct tcphdr *tcph = (struct tcphdr *)((uint8 *)iph + (iph->ihl * 4));
            if (80 == ntohs(tcph->dest) || 8080 == ntohs(tcph->dest))
                return TRUE;
        }
    }
    else
    {
        struct ethhdr *ethh = eth_hdr(skb);
        struct iphdr *iph = http_iphdr(skb);
        if (htons(ETH_P_IP) == ethh->h_proto
            && IPPROTO_TCP == iph->protocol)
        {
            struct tcphdr *tcph = (struct tcphdr *)((uint8 *)iph + (iph->ihl * 4));
            if (80 == ntohs(tcph->dest) || 8080 == ntohs(tcph->dest))
                return TRUE;
        }
    }
    return FALSE;
}
static inline BOOL is_https(struct sk_buff *skb)
{
    struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph = http_iphdr(skb);
    if (htons(ETH_P_IP) == ethh->h_proto
        && IPPROTO_TCP == iph->protocol)
    {
        struct tcphdr *tcph = (struct tcphdr *)((uint8 *)iph + (iph->ihl * 4));
        if (443 == ntohs(tcph->dest))
            return TRUE;
    }
    return FALSE;
}

static inline BOOL is_http_from_server(struct sk_buff *skb)
{
    struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph = http_iphdr(skb);
    if (htons(ETH_P_IP) == ethh->h_proto
        && IPPROTO_TCP == iph->protocol)
    {
        struct tcphdr *tcph = (struct tcphdr *)((uint8 *)iph + (iph->ihl * 4));
        if (80 == ntohs(tcph->source) || 8080 == ntohs(tcph->source))
            return TRUE;
    }
    return FALSE;
}
int32 http_portal_redirect(struct sk_buff *skb,
                           const int8 *url);
int32 http_advertising_redirect(struct sk_buff *skb,
                                const int8 *url);
int32 http_init(const uint32 count);
void http_destroy(void);

#ifdef  __cplusplus
}
#endif

#endif /*__HTTP_H__*/

