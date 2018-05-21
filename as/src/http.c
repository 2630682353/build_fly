#include "http.h"
#include "debug.h"
#include "klog.h"
#include "memcache.h"
#include "spinlock.h"
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/tcp.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <net/ip.h>
#include <linux/kthread.h>
#include <linux/preempt.h>

static struct sk_buff *http_skb_alloc(const struct sk_buff *skb,
                                      const uint32 size)
{
    uint32 nskb_size;
    struct sk_buff *nskb = NULL;
    if (skb_from_vlan_dev(skb))
        nskb_size = sizeof(struct vlan_ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size;
    else
        nskb_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size;
    nskb = alloc_skb(nskb_size, GFP_ATOMIC);
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

static void http_mac_header_fill(struct sk_buff *skb1,
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

static void http_network_header_fill(struct sk_buff *skb1,
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

static void http_transport_header_fill(struct sk_buff *skb1,
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
    /*此处必须注意: 
     *因为在tcp头校验的时候需要用到报文的源/目的IP,
     *所以此处以收到报文的目的/源来作为待发送报文的源/目的IP地址*/
    tcph1->check = csum_tcpudp_magic(iph2->daddr, iph2->saddr, 
                                     tcph1_len + dlen, IPPROTO_TCP, 
                                     tcph1_csum);
}

static int32 http_skb_xmit(struct sk_buff *skb)
{
    int32 ret;
    
    if (skb_from_vlan_dev(skb))
        skb_push(skb, sizeof(struct vlan_ethhdr));
    else
        skb_push(skb, sizeof(struct ethhdr));

    //DB_INF("before xmit: skb->users:%d", skb->users);
    ret = dev_queue_xmit(skb);
    //DB_INF("after xmit: skb->users:%d", skb->users);
    if (0 != ret)
    {
        DB_ERR("dev_queue_xmit() call fail. errno:%d.", ret);
        kfree_skb(skb);
        return -1;
    }
    return 0;
}

static int32 http_ack_reply(struct sk_buff *skb)
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
    struct iphdr *iph = NULL;
    //DB_INF("Http redirect reply.");
    ret = http_ack_reply(skb);
    if (0 != ret)
    {
        DB_ERR("http_ack_reply() call fail.");
        /*LOGGING_ERR("Portal redirect fail for ack-reply. hwaddr["MACSTR"],ipaddr["IPSTR"],url[%s].", 
                MAC2STR(eth_hdr(skb)->h_source), IP2STR(http_iphdr(skb)->saddr), http_url);*/
        return ret;
    }
    iph = http_iphdr(skb);
    /*只针对非IOS设备,IOS设备需后续再作扩展*/
    if (skb_from_vlan_dev(skb))
    {
        struct vlan_ethhdr *vethh = vlan_eth_hdr(skb);
        http_dlen = sprintf(http_data,
                           "HTTP/1.1 302 Found\r\n"
                           "Location: %s&mac="MACSTR"&ip="IPSTR"&vlan=%u\r\n"
                           "Content-Type: text/plain\r\n"
                           "Connection: close\r\n"
                           "Server: Apache-Coyote/1.1\r\n"
                           "Content-Length: 0\r\n"
                           "\r\n",
                           http_url,
                           MAC2STR(vethh->h_source),
                           IP2STR(iph->saddr),
                           ntohs(vethh->h_vlan_TCI));
    }
    else
    {
        struct ethhdr *ethh = eth_hdr(skb);
        http_dlen = sprintf(http_data,
                           "HTTP/1.1 302 Found\r\n"
                           "Location: %s&mac="MACSTR"&ip="IPSTR"&vlan=%u\r\n"
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
        /*(LOGGING_ERR("Portal redirect fail for skb-alloc. hwaddr["MACSTR"],ipaddr["IPSTR"],url[%s].", 
                MAC2STR(eth_hdr(skb)->h_source), IP2STR(http_iphdr(skb)->saddr), http_url);*/
        return -1;
    }
    http_transport_header_fill(nskb, skb, http_data, http_dlen, FALSE, TRUE, TRUE, FALSE);
    http_network_header_fill(nskb, skb, sizeof(struct tcphdr) + http_dlen);
    http_mac_header_fill(nskb, skb);
    ret = http_skb_xmit(nskb);
    if (0 != ret)
    {
        DB_ERR("http_skb_xmit() call fail.");
        /*LOGGING_ERR("Portal redirect fail for skb-xmit. hwaddr["MACSTR"],ipaddr["IPSTR"],url[%s].", 
                MAC2STR(eth_hdr(skb)->h_source), IP2STR(http_iphdr(skb)->saddr), http_url);*/
    }
    /*else
        LOGGING_INFO("Portal redirect successfully. hwaddr["MACSTR"],ipaddr["IPSTR"],url[%s].", 
                MAC2STR(eth_hdr(skb)->h_source), IP2STR(http_iphdr(skb)->saddr), http_url);*/
    return ret;
}

static int32 http_portal_redirect_inner(struct sk_buff *skb,
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
        if (tcph->psh || tcp_dlen > 0)
        {
            int8 *tcpdata = (int8 *)tcph + tcph->doff * 4;
            if (is_http_get_request(tcpdata))
            {/*
                if (http_is_ios_detect(skb))
                    return http_ios_detect_reply(skb);*/
                return http_redirect(skb, url);
            }
        }
    }
    return -1;
}

static int32 http_advertising_redirect_inner(struct sk_buff *skb,
                                             const int8 *url)
{
    int32 ret;
    struct sk_buff *nskb = NULL;
    int8 http_data[512];
    uint32 http_dlen = 0;
    
    ret = http_ack_reply(skb);
    if (0 != ret)
    {
        DB_ERR("http_ack_reply() call fail.");
        /*LOGGING_ERR("Advertising redirect fail for ack-reply. hwaddr["MACSTR"],ipaddr["IPSTR"],url[%s].", 
                MAC2STR(eth_hdr(skb)->h_source), IP2STR(http_iphdr(skb)->saddr), url);*/
        return ret;
    }
    
    http_dlen = sprintf(http_data,
                       "HTTP/1.1 302 Found\r\n"
                       "Location: %s\r\n"
                       "Content-Type: text/plain\r\n"
                       "Connection: close\r\n"
                       "Server: Apache-Coyote/1.1\r\n"
                       "Content-Length: 0\r\n"
                       "\r\n",
                       url);
    nskb = http_skb_alloc(skb, http_dlen);
    if (NULL == nskb)
    {
        DB_ERR("http_skb_alloc() call fail.");
        /*LOGGING_ERR("Advertising redirect fail for skb-alloc. hwaddr["MACSTR"],ipaddr["IPSTR"],url[%s].", 
                MAC2STR(eth_hdr(skb)->h_source), IP2STR(http_iphdr(skb)->saddr), url);*/
        return -1;
    }
    http_transport_header_fill(nskb, skb, http_data, http_dlen, FALSE, TRUE, TRUE, FALSE);
    http_network_header_fill(nskb, skb, sizeof(struct tcphdr) + http_dlen);
    http_mac_header_fill(nskb, skb);
    ret = http_skb_xmit(nskb);
    if (0 != ret)
    {
        DB_ERR("http_skb_xmit() call fail.");
        /*LOGGING_ERR("Advertising redirect fail for skb-xmit. hwaddr["MACSTR"],ipaddr["IPSTR"],url[%s].", 
                MAC2STR(eth_hdr(skb)->h_source), IP2STR(http_iphdr(skb)->saddr), url);*/
        return ret;
    }
    /*LOGGING_INFO("Advertising redirect successfully. hwaddr["MACSTR"],ipaddr["IPSTR"],url[%s].", 
            MAC2STR(eth_hdr(skb)->h_source), IP2STR(http_iphdr(skb)->saddr), url);*/
    return 0;
}

#ifdef HTTP_REDIRECT_KTHREAD
typedef enum http_redirect_type_en{
    HTTP_REDIRECT_TYPE_PORTAL       = 0,
    HTTP_REDIRECT_TYPE_ADVERTISING  = 1,
}http_redirect_type_e;
typedef struct http_redirect_st{
    struct list_head list;
    struct sk_buff *skb;
    int32 type;
    int8 url[URL_SIZE];
}http_redirect_t;
static LIST_HEAD(s_list_http_redirect);
static spinlock_t s_spinlock_http_redirect;
static memcache_t *sp_cache_http_redirect = NULL;
static struct task_struct *sp_kthd_http_redirect = NULL;
static BOOL s_http_inited = FALSE;

static int32 http_redirect_thread_cb(void *data)
{
    while (!kthread_should_stop())
    {
        spinlock_lock_bh(&s_spinlock_http_redirect);
        if (list_empty(&s_list_http_redirect))
        {
            spinlock_unlock_bh(&s_spinlock_http_redirect);
            set_current_state(TASK_UNINTERRUPTIBLE);
            schedule();
            continue;
        }
        
        while (!list_empty(&s_list_http_redirect))
        {
            http_redirect_t *http;
            http = list_first_entry(&s_list_http_redirect, http_redirect_t, list);
            list_del(&http->list);
            spinlock_unlock_bh(&s_spinlock_http_redirect);

            switch (http->type)
            {
            case HTTP_REDIRECT_TYPE_PORTAL:
                http_portal_redirect_inner(http->skb, http->url);
                break;
            case HTTP_REDIRECT_TYPE_ADVERTISING:
                http_advertising_redirect_inner(http->skb, http->url);
                break;
            default:
                break;
            }
            
            kfree_skb(http->skb);
            spinlock_lock_bh(&s_spinlock_http_redirect);
            memcache_free(sp_cache_http_redirect, http);
        }
        spinlock_unlock_bh(&s_spinlock_http_redirect);
    }
    return 0;
}
#endif

int32 http_portal_redirect(struct sk_buff *skb,
                           const int8 *url)
{
#ifdef HTTP_REDIRECT_KTHREAD
    http_redirect_t *http;
    if (FALSE == s_http_inited)
        return -1;
    spinlock_lock(&s_spinlock_http_redirect);
    http = (http_redirect_t *)memcache_alloc(sp_cache_http_redirect);
    if (NULL != http)
    {
        bzero(http, sizeof(*http));
        http->skb = skb_get(skb);
        http->type = HTTP_REDIRECT_TYPE_PORTAL;
        strncpy(http->url, url, sizeof(http->url)-1);
        list_add_tail(&http->list, &s_list_http_redirect);
        spinlock_unlock(&s_spinlock_http_redirect);
        if (NULL != sp_kthd_http_redirect && TASK_RUNNING != sp_kthd_http_redirect->state)
            wake_up_process(sp_kthd_http_redirect);
    }
    else
        spinlock_unlock(&s_spinlock_http_redirect);
    return 0;
#else
    return http_portal_redirect_inner(skb, url);
#endif
}

int32 http_advertising_redirect(struct sk_buff *skb,
                                const int8 *url)
{
#ifdef HTTP_REDIRECT_KTHREAD
    http_redirect_t *http;
    if (FALSE == s_http_inited)
        return -1;
    spinlock_lock(&s_spinlock_http_redirect);
    http = (http_redirect_t *)memcache_alloc(sp_cache_http_redirect);
    if (NULL != http)
    {
        bzero(http, sizeof(*http));
        http->skb = skb_get(skb);
        http->type = HTTP_REDIRECT_TYPE_ADVERTISING;
        strncpy(http->url, url, sizeof(http->url)-1);
        list_add_tail(&http->list, &s_list_http_redirect);
        spinlock_unlock(&s_spinlock_http_redirect);
        if (NULL != sp_kthd_http_redirect && TASK_RUNNING != sp_kthd_http_redirect->state)
            wake_up_process(sp_kthd_http_redirect);
    }
    else
        spinlock_unlock(&s_spinlock_http_redirect);
    return 0;
#else
    return http_advertising_redirect_inner(skb, url);
#endif
}

#ifdef HTTP_REDIRECT_KTHREAD
int32 http_init(const uint32 count)
{
    int32 ret = -1;
    if (TRUE == s_http_inited)
        return 0;
    sp_cache_http_redirect = memcache_create(sizeof(http_redirect_t), count);
    if (NULL == sp_cache_http_redirect)
    {
        DB_ERR("memcache_create() call fail for http-redirect cache.");
        return ret;
    }
    spinlock_init(&s_spinlock_http_redirect);
    sp_kthd_http_redirect = kthread_create(http_redirect_thread_cb, NULL, "kthd-http");
    if (unlikely(IS_ERR(sp_kthd_http_redirect)))
    {
        ret = PTR_ERR(sp_kthd_http_redirect);
        DB_ERR("kthread_create() call fail. errno[%d].", ret);
        sp_kthd_http_redirect = NULL;
        spinlock_destroy(&s_spinlock_http_redirect);
        memcache_destroy(sp_cache_http_redirect);
        sp_cache_http_redirect = NULL;
    }
    else
    {
        ret = 0;
        s_http_inited = TRUE;
    }
    return ret;
}

void http_destroy(void)
{
    http_redirect_t *http;
    if (FALSE == s_http_inited)
        return;
    s_http_inited = FALSE;
    kthread_stop(sp_kthd_http_redirect);
    spinlock_lock_bh(&s_spinlock_http_redirect);
    while (!list_empty(&s_list_http_redirect))
    {
        http = list_first_entry(&s_list_http_redirect, http_redirect_t, list);
        list_del(&http->list);
        memcache_free(sp_cache_http_redirect, http);
    }
    spinlock_unlock_bh(&s_spinlock_http_redirect);
    memcache_destroy(sp_cache_http_redirect);
    spinlock_destroy(&s_spinlock_http_redirect);
}
#endif
