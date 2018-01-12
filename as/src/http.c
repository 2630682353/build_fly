#include "http.h"
#include "debug.h"
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ip.h>


static int32 http_ack_reply(struct sk_buff *skb)
{
    struct ethhdr *ethh = NULL;
    struct iphdr *iph = NULL;
    struct tcphdr *tcph = NULL;
    struct sk_buff *skb2 = NULL;
    uint32 skb2_size;
    struct ethhdr *ethh2 = NULL;
    struct iphdr *iph2 = NULL;
    struct tcphdr *tcph2 = NULL;
    uint32 tcp_dlen;
    int32 tcph_len;
    __wsum tcph_csum;
    int32 ret;

    //DB_INF("ACK.");
    ethh = eth_hdr(skb);
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((uint8 *)(ethh+1) + iph->ihl*4);
    if (tcph->syn || tcph->fin)
        tcp_dlen = 1;
    else
        tcp_dlen = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
    
    skb2_size = sizeof(*ethh2) + sizeof(*iph2) + sizeof(*tcph2);
    skb2 = alloc_skb(skb2_size, GFP_KERNEL);
    skb_put(skb2, skb2_size);
    skb_reset_mac_header(skb2);
    skb_pull(skb2, sizeof(*ethh2));
    skb_reset_network_header(skb2);
    skb2->dev = skb->dev;
    skb2->protocol = skb->protocol;
    
    ethh2 = eth_hdr(skb2);
    memcpy(ethh2->h_dest, ethh->h_source, sizeof(ethh2->h_dest));
    memcpy(ethh2->h_source, ethh->h_dest, sizeof(ethh2->h_source));
    ethh2->h_proto = ethh->h_proto;
    
    iph2 = ip_hdr(skb2);
    iph2->ihl = sizeof(*iph2) >> 2;
    iph2->version = 4;
    iph2->tos = 0;
    iph2->tot_len = htons(sizeof(*tcph2) + sizeof(*iph2));
    iph2->id = iph->id;
    iph2->frag_off = htons(IP_DF);
    iph2->ttl = 64;
    iph2->protocol = IPPROTO_TCP;
    iph2->check = 0;
    iph2->saddr = iph->daddr;
    iph2->daddr = iph->saddr;

    tcph2 = (struct tcphdr *)(skb2->data + iph2->ihl * 4);
    tcph2->source = tcph->dest;
    tcph2->dest = tcph->source;
    tcph2->seq = tcph->ack_seq;
    tcph2->ack_seq = htonl(ntohl(tcph->seq) + tcp_dlen);
    tcph2->res1 = 0;
    tcph2->doff = sizeof(*tcph2) >> 2;
    tcph2->fin = 0;
    tcph2->syn = 0;
    tcph2->rst = 0;
    tcph2->psh = 0;
    tcph2->ack = 1;
    tcph2->urg = 0;
    tcph2->ece = 0;
    tcph2->cwr = 0;
    tcph2->window = tcph->window;
    tcph2->check = 0;
    tcph2->urg_ptr = 0;
    
    ip_send_check(iph2);
    tcph_len = tcph2->doff * 4;
    tcph_csum = csum_partial((void *)tcph2, tcph_len, 0);
    tcph2->check = csum_tcpudp_magic(iph2->saddr, iph2->daddr, tcph_len, IPPROTO_TCP, tcph_csum);
    /* reset to ether mac */
    skb_push(skb2, ETH_HLEN);
    /* send */
    ret = dev_queue_xmit(skb2);
    if (0 != ret)
    {
        DB_ERR("dev_queue_xmit() call failed. errno:%d.", ret);
        kfree_skb(skb2);
        return -1;
    }
    return 0;
}

static int32 http_fin_reply(struct sk_buff *skb)
{
    int32 tcph_len;
    __wsum tcph_csum;
    struct ethhdr *ethh;
    struct iphdr *iph;
    struct tcphdr *tcph;
    uint32 tcp_dlen;
    struct sk_buff *skb2 = NULL;
    uint32 skb2_size;
    struct ethhdr *ethh2;
    struct iphdr *iph2;
    struct tcphdr *tcph2;
    int32 ret;
        
    //DB_INF("Disconnect HTTP connection.");
    
    ret = http_ack_reply(skb);
    if (0 != ret)
    {
        DB_ERR("http_ack_reply() fail.");
        return -1;
    }

    ethh = eth_hdr(skb);
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((uint8 *)(ethh+1) + iph->ihl*4);
    tcp_dlen = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
    if (tcph->fin)
        tcp_dlen += 1;
    
    skb2_size = sizeof(*ethh2) + sizeof(*iph2) + sizeof(*tcph2);
    skb2 = alloc_skb(skb2_size, GFP_KERNEL);
    skb_put(skb2, skb2_size);
    skb_reset_mac_header(skb2);
    skb_pull(skb2, sizeof(*ethh2));
    skb_reset_network_header(skb2);
    skb2->dev = skb->dev;
    skb2->protocol = skb->protocol;
    
    ethh2 = eth_hdr(skb2);
    memcpy(ethh2->h_dest, ethh->h_source, sizeof(ethh2->h_dest));
    memcpy(ethh2->h_source, ethh->h_dest, sizeof(ethh2->h_source));
    ethh2->h_proto = ethh->h_proto;
    
    iph2 = ip_hdr(skb2);
    iph2->ihl = sizeof(*iph2) >> 2;
    iph2->version = 4;
    iph2->tos = 0;
    iph2->tot_len = htons(sizeof(*tcph2) + sizeof(*iph2));
    iph2->id = iph->id;
    iph2->frag_off = htons(IP_DF);
    iph2->ttl = 64;
    iph2->protocol = IPPROTO_TCP;
    iph2->check = 0;
    iph2->saddr = iph->daddr;
    iph2->daddr = iph->saddr;

    tcph2 = (struct tcphdr *)(skb2->data + iph2->ihl * 4);
    tcph2->source = tcph->dest;
    tcph2->dest = tcph->source;
    tcph2->seq = tcph->ack_seq;
    tcph2->ack_seq = htonl(ntohl(tcph->seq) + tcp_dlen);
    tcph2->res1 = 0;
    tcph2->doff = sizeof(*tcph2) >> 2;
    tcph2->fin = 1;
    tcph2->syn = 0;
    tcph2->rst = 0;
    tcph2->psh = 0;
    tcph2->ack = 1;
    tcph2->urg = 0;
    tcph2->ece = 0;
    tcph2->cwr = 0;
    tcph2->window = tcph->window;
    tcph2->check = 0;
    tcph2->urg_ptr = 0;
    
    ip_send_check(iph2);
    tcph_len = tcph2->doff * 4;
    tcph_csum = csum_partial((void *)tcph2, tcph_len, 0);
    tcph2->check = csum_tcpudp_magic(iph2->saddr, iph2->daddr, tcph_len, IPPROTO_TCP, tcph_csum);
    /* reset to ether mac */
    skb_push(skb2, ETH_HLEN);
    /* send */
    ret = dev_queue_xmit(skb2);
    if (0 != ret)
    {
        DB_ERR("dev_queue_xmit() call failed. errno:%d.", ret);
        kfree_skb(skb2);
        return -1;
    }
    return 0;
}

static int32 http_syn_reply(struct sk_buff *skb)
{
    int32 tcph_len;
    __wsum tcph_csum;
    struct ethhdr *ethh;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct sk_buff *skb2 = NULL;
    uint32 skb2_size;
    struct ethhdr *ethh2;
    struct iphdr *iph2;
    struct tcphdr *tcph2;
    int32 ret;
        
    //DB_INF("HTTP connections.");
    
    ethh = eth_hdr(skb);
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((uint8 *)(ethh+1) + iph->ihl*4);
    
    skb2_size = sizeof(*ethh2) + sizeof(*iph2) + sizeof(*tcph2);
    skb2 = alloc_skb(skb2_size, GFP_KERNEL);
    skb_put(skb2, skb2_size);
    skb_reset_mac_header(skb2);
    skb_pull(skb2, sizeof(*ethh2));
    skb_reset_network_header(skb2);
    skb2->dev = skb->dev;
    skb2->protocol = skb->protocol;
    
    ethh2 = eth_hdr(skb2);
    memcpy(ethh2->h_dest, ethh->h_source, sizeof(ethh2->h_dest));
    memcpy(ethh2->h_source, ethh->h_dest, sizeof(ethh2->h_source));
    ethh2->h_proto = ethh->h_proto;
    
    iph2 = ip_hdr(skb2);
    iph2->ihl = sizeof(*iph2) >> 2;
    iph2->version = 4;
    iph2->tos = 0;
    iph2->tot_len = htons(sizeof(*tcph2) + sizeof(*iph2));
    iph2->id = iph->id;
    iph2->frag_off = htons(IP_DF);
    iph2->ttl = 64;
    iph2->protocol = IPPROTO_TCP;
    iph2->check = 0;
    iph2->saddr = iph->daddr;
    iph2->daddr = iph->saddr;

    tcph2 = (struct tcphdr *)(skb2->data + iph2->ihl * 4);
    tcph2->source = tcph->dest;
    tcph2->dest = tcph->source;
    tcph2->seq = 0;
    tcph2->ack_seq = htonl(ntohl(tcph->seq) + 1);
    tcph2->res1 = 0;
    tcph2->doff = sizeof(*tcph2) >> 2;
    tcph2->fin = 0;
    tcph2->syn = 1;
    tcph2->rst = 0;
    tcph2->psh = 0;
    tcph2->ack = 1;
    tcph2->urg = 0;
    tcph2->ece = 0;
    tcph2->cwr = 0;
    tcph2->window = tcph->window;
    tcph2->check = 0;
    tcph2->urg_ptr = 0;
    
    ip_send_check(iph2);
    tcph_len = tcph2->doff * 4;
    tcph_csum = csum_partial((void *)tcph2, tcph_len, 0);
    tcph2->check = csum_tcpudp_magic(iph2->saddr, iph2->daddr, tcph_len, IPPROTO_TCP, tcph_csum);
    /* reset to ether mac */
    skb_push(skb2, ETH_HLEN);
    /* send */
    ret = dev_queue_xmit(skb2);
    if (0 != ret)
    {
        DB_ERR("dev_queue_xmit() call failed. errno:%d.", ret);
        kfree_skb(skb2);
        return -1;
    }
    return 0;
}

static int32 http_redirect(struct sk_buff *skb,
                           const uint8 *http_url)
{
    int32 buff_len, tcph_len, iph_len;
    uint32 tcp_dlen;
    __wsum tcph_csum;
    struct ethhdr *ethh;
    struct iphdr *iph;
    struct tcphdr *tcph;
    struct sk_buff *skb2;
    uint32 skb2_size;
    struct ethhdr *ethh2;
    struct iphdr *iph2;
    struct tcphdr *tcph2;
    uint8 redirect_buf[512];
    int32 ret;

    //DB_INF("Portal redirects.");

    ethh = eth_hdr(skb);
    iph = ip_hdr(skb);
    iph_len = iph->ihl * 4;
    tcph = (struct tcphdr *)(skb->data + iph_len);
    tcph_len = tcph->doff * 4;
    tcp_dlen = ntohs(iph->tot_len) - iph_len - tcph_len;
    
    ret = http_ack_reply(skb);
    if (0 != ret)
    {
        DB_ERR("http_ack_reply() fail.");
        return -1;
    }
    
    /*只针对非IOS设备,IOS设备需后续再作扩展*/
    buff_len = sprintf(redirect_buf,
                       "HTTP/1.1 302 Found\r\n"
                       "Location: %s?opt=login&mac="MACSTR"&ip="IPSTR"\r\n"
                       "Content-Type: text/plain\r\n"
                       "Connection: close\r\n"
                       "Server: Apache-Coyote/1.1\r\n"
                       "Content-Length: 0\r\n"
                       "\r\n",
                       http_url,
                       MAC2STR(ethh->h_source),
                       IP2STR(iph->saddr));

    skb2_size = buff_len + sizeof(*ethh2) + sizeof(*iph2) + sizeof(*tcph2);
    skb2 = alloc_skb(skb2_size, GFP_KERNEL);
    skb_put(skb2, skb2_size);
    skb_reset_mac_header(skb2);
    skb_pull(skb2, sizeof(*ethh2));
    skb_reset_network_header(skb2);
    skb_pull(skb2, sizeof(*iph2));
    skb_reset_transport_header(skb2);
    skb_pull(skb2, sizeof(*tcph2));
    skb2->dev = skb->dev;
    skb2->protocol = skb->protocol;

    ethh2 = eth_hdr(skb2);
    memcpy(ethh2->h_dest, ethh->h_source, sizeof(ethh2->h_dest));
    memcpy(ethh2->h_source, ethh->h_dest, sizeof(ethh2->h_dest));
    ethh2->h_proto = ethh->h_proto;
    
    iph2            = ip_hdr(skb2);
    iph2->ihl       = sizeof(*iph2) >> 2;
    iph2->version   = 4;
    iph2->tos       = 0;
    iph2->tot_len   = htons(buff_len + sizeof(*iph2) + sizeof(*tcph2));
    iph2->id        = htons(0);
    iph2->frag_off  = htons(IP_DF);
    iph2->ttl       = iph->ttl;
    iph2->protocol  = IPPROTO_TCP;
    iph2->check     = 0;
    iph2->saddr     = iph->daddr;
    iph2->daddr     = iph->saddr;

    tcph2           = tcp_hdr(skb2);
    tcph2->source   = tcph->dest;
    tcph2->dest     = tcph->source;
    tcph2->ack_seq  = htonl(ntohl(tcph->seq) + tcp_dlen);
    tcph2->seq      = tcph->ack_seq;
    tcph2->doff     = sizeof(*tcph2) >> 2;
    tcph2->res1     = 0;
    tcph2->cwr      = 0;
    tcph2->ece      = 0;
    tcph2->urg      = 0;
    tcph2->ack      = 1;
    tcph2->psh      = 1;
    tcph2->rst      = 0;
    tcph2->syn      = 0;
    tcph2->fin      = 0; //fin
    tcph2->check    = 0;
    tcph2->urg_ptr  = 0;

    memcpy(skb2->data, redirect_buf, buff_len);
    
    skb_push(skb2, sizeof(*tcph2));
    skb_push(skb2, sizeof(*iph2));
    skb_push(skb2, sizeof(*ethh2));

    ip_send_check(iph2);
    tcph_csum = csum_partial((void *)tcph2, (sizeof(*tcph2) + buff_len), 0);
    tcph2->check = 0;
    tcph2->check = csum_tcpudp_magic(iph2->saddr, iph2->daddr, (sizeof(*tcph2) + buff_len), IPPROTO_TCP, tcph_csum);

    ret = dev_queue_xmit(skb2);
    if (0 != ret)
    {
        DB_ERR("dev_queue_xmit() call fail. errno:%d.", ret);
        kfree_skb(skb2);
        return -1;
    }
    return 0;
}

int32 http_check_inner_reply(struct sk_buff *skb,
                             const uint8 *http_url)
{
    struct ethhdr *ethh;
    struct iphdr *iph;
    struct tcphdr *tcph;

    if (NULL == skb || NULL == http_url)
        return -1;
    
    ethh = eth_hdr(skb);
    iph = ip_hdr(skb);
    tcph = (struct tcphdr *)((uint8 *)(ethh + 1) + iph->ihl * 4);
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
                return http_redirect(skb, http_url);
        }
    }
    return -1;
}
