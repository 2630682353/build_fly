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

static inline struct sk_buff *http_skb_alloc(const struct sk_buff *skb,
                                             const uint32 size)
{
    uint32 nskb_size;
    struct sk_buff *nskb = NULL;
    if (skb_from_vlan_dev(skb))
        nskb_size = sizeof(struct vlan_ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size;
    else
        nskb_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size;
    nskb = alloc_skb(nskb_size, GFP_KERNEL);
    if (NULL == nskb)
        return NULL;
    skb_put(nskb, nskb_size);
    skb_reset_mac_header(nskb);
    if (skb_from_vlan_dev(skb))
        skb_pull(nskb, sizeof(struct vlan_ethhdr));
    else
        skb_pull(nskb, sizeof(struct ethhdr));
    skb_reset_network_header(nskb);
    nskb->dev = skb->dev;
    nskb->protocol = skb->protocol;
    return nskb;
}

static inline void http_mac_header_fill(struct sk_buff *skb1,
                                        const struct sk_buff *skb2)
{
    if (skb_from_vlan_dev(skb2))
    {
        struct vlan_ethhdr *vethh1 = vlan_eth_hdr(skb1);
        struct vlan_ethhdr *vethh2 = vlan_eth_hdr(skb2);
        memcpy(vethh1->h_dest, vethh2->h_source, sizeof(vethh1->h_dest));
        memcpy(vethh1->h_source, vethh2->h_dest, sizeof(vethh1->h_source));
        vethh1->h_vlan_proto = vethh2->h_vlan_proto;
        vethh1->h_vlan_TCI = vethh2->h_vlan_TCI;
        vethh1->h_vlan_encapsulated_proto = vethh2->h_vlan_encapsulated_proto;
    }
    else
    {
        struct ethhdr *ethh1 = eth_hdr(skb1);
        struct ethhdr *ethh2 = eth_hdr(skb2);
        memcpy(ethh1->h_dest, ethh2->h_source, sizeof(ethh1->h_dest));
        memcpy(ethh1->h_source, ethh2->h_dest, sizeof(ethh1->h_source));
        ethh1->h_proto = ethh2->h_proto;
    }
}

static inline void http_network_header_fill(struct sk_buff *skb1,
                                            const struct sk_buff *skb2,
                                            const uint32 dlen)
{
    struct iphdr *iph1 = ip_hdr(skb1);
    struct iphdr *iph2 = http_iphdr(skb2);
    iph1->ihl = sizeof(*iph1) >> 2;
    iph1->version = 4;
    iph1->tos = 0;
    iph1->tot_len = htons(dlen + sizeof(*iph1));
    iph1->id = iph2->id;
    iph1->frag_off = htons(IP_DF);
    iph1->ttl = 64;
    iph1->protocol = IPPROTO_TCP;
    iph1->check = 0;
    iph1->saddr = iph2->daddr;
    iph1->daddr = iph2->saddr;
    ip_send_check(iph1);
}

static inline void http_transport_header_fill(struct sk_buff *skb1,
                                              const struct sk_buff *skb2,
                                              const int8 *data,
                                              const uint32 dlen,
                                              const BOOL flag_syn,
                                              const BOOL flag_ack,
                                              const BOOL flag_psh,
                                              const BOOL flag_fin)
{
    struct iphdr *iph1 = ip_hdr(skb1);
    struct iphdr *iph2 = http_iphdr(skb2);
    struct tcphdr *tcph1 = (struct tcphdr *)(iph1 + 1);
    struct tcphdr *tcph2 = (struct tcphdr *)((int8 *)iph2 + (iph2->ihl * 4));
    uint32 tcpd2_len;
    uint32 tcph1_len;
    __wsum tcph1_csum;

    tcpd2_len = ntohs(iph2->tot_len) - (iph2->ihl * 4) - (tcph2->doff * 4);
    if (tcph2->syn || tcph2->fin)
        tcpd2_len += 1;
    //DB_INF("tcpd2_len:%u.", tcpd2_len);
    
    tcph1->source = tcph2->dest;
    tcph1->dest = tcph2->source;
    if (flag_syn)
        tcph1->seq = 0;
    else
        tcph1->seq = tcph2->ack_seq;
    tcph1->ack_seq = htonl(ntohl(tcph2->seq) + tcpd2_len);
    tcph1->res1 = 0;
    tcph1->doff = sizeof(*tcph1) >> 2;
    tcph1->fin = flag_fin ? 1 : 0;
    tcph1->syn = flag_syn ? 1 : 0;
    tcph1->rst = 0;
    tcph1->psh = flag_psh ? 1 : 0;
    tcph1->ack = flag_ack ? 1 : 0;
    tcph1->urg = 0;
    tcph1->ece = 0;
    tcph1->cwr = 0;
    tcph1->window = tcph2->window;
    tcph1->check = 0;
    tcph1->urg_ptr = 0;
    tcph1_len = tcph1->doff * 4;

    if (flag_psh && NULL != data && dlen > 0)
    {
        int8 *tcpd1 = NULL;
        tcpd1 = (int8 *)tcph1 + tcph1_len;
        memcpy(tcpd1, data, dlen);
    }
    
    tcph1_csum = csum_partial((void *)tcph1, tcph1_len + dlen, 0);
    /*�˴�����ע��: 
     *��Ϊ��tcpͷУ���ʱ����Ҫ�õ����ĵ�Դ/Ŀ��IP,
     *���Դ˴����յ����ĵ�Ŀ��/Դ����Ϊ�����ͱ��ĵ�Դ/Ŀ��IP��ַ*/
    tcph1->check = csum_tcpudp_magic(iph2->daddr, iph2->saddr, 
                                     tcph1_len + dlen, IPPROTO_TCP, 
                                     tcph1_csum);
}

static inline int32 http_skb_xmit(struct sk_buff *skb)
{
    int32 ret;
    
    if (skb_from_vlan_dev(skb))
        skb_push(skb, sizeof(struct vlan_ethhdr));
    else
        skb_push(skb, sizeof(struct ethhdr));
    
    ret = dev_queue_xmit(skb);
    if (0 != ret)
    {
        DB_ERR("dev_queue_xmit() call fail. errno:%d.", ret);
        kfree_skb(skb);
        return -1;
    }
    return 0;
}

static inline int32 http_ack_reply(struct sk_buff *skb)
{
    int32 ret;
    struct sk_buff *nskb = http_skb_alloc(skb, 0);
    //DB_INF("Http ack reply.");
    if (NULL == nskb)
    {
        DB_ERR("http_skb_alloc() call fail.");
        return -1;
    }
    http_transport_header_fill(nskb, skb, NULL, 0, FALSE, TRUE, FALSE, FALSE);
    http_network_header_fill(nskb, skb, sizeof(struct tcphdr));
    http_mac_header_fill(nskb, skb);
    ret = http_skb_xmit(nskb);
    if (0 != ret)
        DB_ERR("http_skb_xmit() call fail.");
    return ret;
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
int32 http_check_inner_reply(struct sk_buff *skb,
                             const int8 *url);

#ifdef  __cplusplus
}
#endif

#endif /*__HTTP_H__*/

