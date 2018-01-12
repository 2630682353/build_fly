#ifndef __HTTP_H__
#define __HTTP_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include "type.h"
#include "def.h"

static inline BOOL is_http_get_request(int8 *data)
{
	return (0 == memcmp(data, "GET", 3)) ? TRUE : FALSE;
}
static inline BOOL is_http(struct sk_buff *skb)
{
    struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    if (htons(ETH_P_IP) == ethh->h_proto
        && IPPROTO_TCP == iph->protocol)
    {
        struct tcphdr *tcph = (struct tcphdr *)((uint8 *)iph + (iph->ihl * 4));
        if (80 == ntohs(tcph->dest) || 8080 == ntohs(tcph->dest))
            return TRUE;
    }
    return FALSE;
}
static inline BOOL is_https(struct sk_buff *skb)
{
    struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
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
    struct iphdr *iph = ip_hdr(skb);
    if (htons(ETH_P_IP) == ethh->h_proto
        && IPPROTO_TCP == iph->protocol)
    {
        struct tcphdr *tcph = (struct tcphdr *)((uint8 *)iph + (iph->ihl * 4));
        if (80 == ntohs(tcph->source) || 8080 == ntohs(tcph->source))
            return TRUE;
    }
    return FALSE;
}
int32 http_check_inner_reply(struct sk_buff *skb,
                             const uint8 *http_url);

#ifdef  __cplusplus
}
#endif

#endif /*__HTTP_H__*/

