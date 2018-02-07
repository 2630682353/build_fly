#include "http.h"
#include "debug.h"
#include "log.h"
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ip.h>

static int32 http_fin_reply(struct sk_buff *skb)
{
    int32 ret;
    struct sk_buff *nskb = NULL;
    //DB_INF("Http fin reply.");
    ret = http_ack_reply(skb);
    if (0 != ret)
    {
        DB_ERR("http_ack_reply() call fail.");
        return ret;
    }
    nskb = http_skb_alloc(skb, 0);
    if (NULL == nskb)
    {
        DB_ERR("http_skb_alloc() call fail.");
        return -1;
    }
    http_transport_header_fill(nskb, skb, NULL, 0, FALSE, TRUE, FALSE, TRUE);
    http_network_header_fill(nskb, skb, sizeof(struct tcphdr));
    http_mac_header_fill(nskb, skb);
    ret = http_skb_xmit(nskb);
    if (0 != ret)
        DB_ERR("http_skb_xmit() call fail.");
    return ret;
}

static int32 http_syn_reply(struct sk_buff *skb)
{
    int32 ret;
    struct sk_buff *nskb = NULL;
    //DB_INF("Http syn reply.");
    nskb = http_skb_alloc(skb, 0);
    if (NULL == nskb)
    {
        DB_ERR("http_skb_alloc() call fail.");
        return -1;
    }
    http_transport_header_fill(nskb, skb, NULL, 0, TRUE, TRUE, FALSE, FALSE);
    http_network_header_fill(nskb, skb, sizeof(struct tcphdr));
    http_mac_header_fill(nskb, skb);
    ret = http_skb_xmit(nskb);
    if (0 != ret)
        DB_ERR("http_skb_xmit() call fail.");
    return ret;
}

static int32 http_redirect(struct sk_buff *skb,
                           const uint8 *http_url)
{
    int32 ret;
    struct sk_buff *nskb = NULL;
    int8 http_data[512];
    uint32 http_dlen = 0;
    struct ethhdr *ethh = eth_hdr(skb);
    struct iphdr *iph = NULL;
    //DB_INF("Http redirect reply.");
    ret = http_ack_reply(skb);
    if (0 != ret)
    {
        DB_ERR("http_ack_reply() call fail.");
        return ret;
    }
    iph = http_iphdr(skb);
    /*只针对非IOS设备,IOS设备需后续再作扩展*/
    if (skb_from_vlan_dev(skb))
    {
        struct vlan_ethhdr *vethh = vlan_eth_hdr(skb);
        http_dlen = sprintf(http_data,
                           "HTTP/1.1 302 Found\r\n"
                           "Location: %s?opt=login&mac="MACSTR"&ip="IPSTR"&vlanid=%u\r\n"
                           "Content-Type: text/plain\r\n"
                           "Connection: close\r\n"
                           "Server: Apache-Coyote/1.1\r\n"
                           "Content-Length: 0\r\n"
                           "\r\n",
                           http_url,
                           MAC2STR(ethh->h_source),
                           IP2STR(iph->saddr),
                           ntohs(vethh->h_vlan_TCI));
    }
    else
    {
        http_dlen = sprintf(http_data,
                           "HTTP/1.1 302 Found\r\n"
                           "Location: %s?opt=login&mac="MACSTR"&ip="IPSTR"&vlanid=%u\r\n"
                           "Content-Type: text/plain\r\n"
                           "Connection: close\r\n"
                           "Server: Apache-Coyote/1.1\r\n"
                           "Content-Length: 0\r\n"
                           "\r\n",
                           http_url,
                           MAC2STR(ethh->h_source),
                           IP2STR(iph->saddr),
                           0);
    }
    nskb = http_skb_alloc(skb, http_dlen);
    if (NULL == nskb)
    {
        DB_ERR("http_skb_alloc() call fail.");
        return -1;
    }
    http_transport_header_fill(nskb, skb, http_data, http_dlen, FALSE, TRUE, TRUE, FALSE);
    http_network_header_fill(nskb, skb, sizeof(struct tcphdr) + http_dlen);
    http_mac_header_fill(nskb, skb);
    ret = http_skb_xmit(nskb);
    if (0 != ret)
        DB_ERR("http_skb_xmit() call fail.");
    return ret;
}

int32 http_check_inner_reply(struct sk_buff *skb,
                             const int8 *url)
{
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (NULL == skb)
        return -1;
    if (0 == strlen(url))
        return 0;
    
    iph = http_iphdr(skb);
    tcph = (struct tcphdr *)(((uint8 *)iph) + iph->ihl * 4);
    /* fin, reply fin + ack */
    if (tcph->fin)
        return http_fin_reply(skb);
    /* syn, reply syn + ack */
    if (tcph->syn && !tcph->ack)
        return http_syn_reply(skb);
    /* push and get, reply redir */
    if (tcph->ack)
    {
        uint32 tcp_dlen = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
        int8 *body;
        body = (int8 *)tcph + tcph->doff * 4;
        if (tcph->psh || tcp_dlen > 0)
        {
            if (is_http_get_request(body))
                return http_redirect(skb, url);
        }
    }
    return -1;
}
