#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/in_route.h>
#include <linux/if_vlan.h>
#include <net/route.h>
#include <net/arp.h>
#include <linux/inetdevice.h>
#include <uapi/linux/netfilter_ipv4.h>

#include "type.h"
#include "blacklist.h"
#include "whitelist.h"
#include "authenticated.h"
#include "advertising.h"
#include "debug.h"
#include "http.h"
#include "time.h"
#include "config.h"
#include "log.h"
#include "portal.h"
#include "vlan.h"

static uint32 ads_maxcount_push = 32;
module_param(ads_maxcount_push, uint, 0555);
MODULE_PARM_DESC(ads_maxcount_push, "The maximum number of Advertising Push!!");

static uint32 ads_maxcount_embed = 32;
module_param(ads_maxcount_embed, uint, 0555);
MODULE_PARM_DESC(ads_maxcount_embed, "The maximum number of Advertising Embed!!");

static uint32 blacklist_maxcount = 128;
module_param(blacklist_maxcount, uint, 0555);
MODULE_PARM_DESC(blacklist_maxcount, "The maximum number of BlackList!!");

static uint32 whitelist_maxcount = 128;
module_param(whitelist_maxcount, uint, 0555);
MODULE_PARM_DESC(whitelist_maxcount, "The maximum number of WhiteList!!");

static uint32 auth_maxcount = 1024;
module_param(auth_maxcount, uint, 0555);
MODULE_PARM_DESC(auth_maxcount, "The maximum number of Authenticated User!!");


static struct proc_dir_entry *sp_proc_access_service = NULL;
#define PROC_ACCESS_SERVICE "as"
static int32 proc_access_service_init(void)
{
    struct proc_dir_entry *entry = proc_mkdir(PROC_ACCESS_SERVICE, NULL);
    if (NULL == entry)
    {
        DB_ERR("proc_mkdir(%s) fail!!", PROC_ACCESS_SERVICE);
        return -1;
    }
    sp_proc_access_service = entry;
    if (0 != portal_proc_init(sp_proc_access_service)
        || 0 != advertising_proc_init(sp_proc_access_service)
        || 0 != blacklist_proc_init(sp_proc_access_service)
        || 0 != whitelist_proc_init(sp_proc_access_service)
        || 0 != authenticated_proc_init(sp_proc_access_service))
    {
        portal_proc_destroy(sp_proc_access_service);
        advertising_proc_destroy(sp_proc_access_service);
        blacklist_proc_destroy(sp_proc_access_service);
        whitelist_proc_destroy(sp_proc_access_service);
        authenticated_proc_destroy(sp_proc_access_service);
        remove_proc_entry(PROC_ACCESS_SERVICE, NULL);
        return -1;
    }
    return 0;
}

static void proc_access_service_destroy(void)
{
    if (NULL != sp_proc_access_service)
    {
        portal_proc_destroy(sp_proc_access_service);
        advertising_proc_destroy(sp_proc_access_service);
        blacklist_proc_destroy(sp_proc_access_service);
        whitelist_proc_destroy(sp_proc_access_service);
        authenticated_proc_destroy(sp_proc_access_service);
        remove_proc_entry(PROC_ACCESS_SERVICE, NULL);
        sp_proc_access_service = NULL;
    }
}

static inline BOOL is_to_local(struct sk_buff *skb)
{
    int32 ret;
    const struct iphdr *iph = http_iphdr(skb);
    /*loop ip addr*/
    if (0x7f000001 == htonl(iph->daddr))
        return TRUE;
    ret = ip_route_input_noref(skb, iph->daddr, iph->saddr, iph->tos, skb->dev);
    if (!unlikely(ret))
    {
        struct rtable *rt = skb_rtable(skb);
        if (RTN_LOCAL == rt->rt_type)
		    return TRUE;
    }
    return FALSE;
}

#define DNS_PORT            (53)
#define DHCP_CLIENT_PORT    (68)
#define DHCP_SERVER_PORT    (67)
static inline BOOL is_bypass(struct sk_buff *skb)
{
    struct iphdr *iph = NULL;
    if (TRUE != portal_skb_exist(skb))
        return TRUE;
    if (skb_from_vlan_dev(skb))
    {
        struct vlan_ethhdr *vethh = vlan_eth_hdr(skb);
        iph = http_iphdr(skb);
        if (htons(ETH_P_IP) != vethh->h_vlan_encapsulated_proto
            || IPPROTO_ICMP == iph->protocol)
            return TRUE;
    }
    else
    {
        struct ethhdr *ethh = eth_hdr(skb);
        iph = http_iphdr(skb);
        if (htons(ETH_P_IP) != ethh->h_proto
            || IPPROTO_ICMP == iph->protocol)
            return TRUE;
    }
    if (IPPROTO_UDP == iph->protocol)
    {
        struct udphdr *udph = (struct udphdr *)((uint8 *)iph + (iph->ihl * 4));
        if (DNS_PORT == ntohs(udph->dest)
            || DHCP_SERVER_PORT == ntohs(udph->dest)
            || DHCP_CLIENT_PORT == ntohs(udph->dest))
            return TRUE;
    }
    return is_to_local(skb);
}

static int32 whitelist_uplink_skb_check(struct sk_buff *skb)
{
    int32 ret = ND_DROP;
    struct ethhdr *ethh = eth_hdr(skb);
    whitelist_t *white = NULL;

    white = whitelist_search(ethh->h_source);
    if (NULL != white)
    {
        whitelist_uplink_update(white);
        ret = ND_ACCEPT;
        DB_INF("User \""MACSTR"\" in whitelist.", MAC2STR(ethh->h_source));
        LOGGING_INFO("User \""MACSTR"\" in whitelist from inside.", MAC2STR(ethh->h_source));
        whitelist_put(white);
    }
    return ret;
}

static int32 blacklist_uplink_skb_check(struct sk_buff *skb)
{
    int32 ret = ND_ACCEPT;
    struct ethhdr *ethh = eth_hdr(skb);
    blacklist_t *black = NULL;

    black = blacklist_search(ethh->h_source);
    if (NULL != black)
    {
        blacklist_uplink_update(black);
        ret = ND_DROP;
        DB_INF("User \""MACSTR"\" in blacklist.", MAC2STR(ethh->h_source));
        LOGGING_INFO("User \""MACSTR"\" in blacklist from inside.", MAC2STR(ethh->h_source));
        blacklist_put(black);
    }
    return ret;
}

static inline int32 portal_url_push(struct sk_buff *skb)
{
    portal_interface_t *interface = NULL;
    portal_vlan_t *vlan = NULL;
    int8 *url = NULL;
    int32 ret = -1;
    if (skb_from_vlan_dev(skb))
    {
        struct vlan_ethhdr *vethh = vlan_eth_hdr(skb);
        vlan = portal_vlan_get(ntohs(vethh->h_vlan_TCI));
        if (NULL != vlan)
            url = vlan->url;
    }
    else
    {
        interface = portal_interface_get(skb->dev->name);
        if (NULL != interface)
            url = interface->url;
    }
    if (NULL == url || strlen(url) <= 0)
        ret = 0;
    else
    {
        //DB_INF("portal-url[%s].", url);
        ret = http_check_inner_reply(skb, url);
    }
    if (NULL != vlan)
        portal_vlan_put(vlan);
    if (NULL != interface)
        portal_interface_put(interface);
    return ret;
}

static int32 authenticated_uplink_skb_check(struct sk_buff *skb)
{
    int32 ret = ND_DROP;
    struct ethhdr *ethh = eth_hdr(skb);
    authenticated_t *auth = NULL;
    auth = authenticated_search(ethh->h_source);
    if (unlikely(NULL == auth))
    {
        if (TRUE == is_http(skb))
            portal_url_push(skb);
        goto out;
    }
    else
    {
        if (unlikely(0 != authenticated_uplink_skb_update(auth, skb)))
        {
            DB_WAR("authenticated_uplink_skb_update() checked, and drop it.");
            goto out;
        }
    }
    ret = ND_ACCEPT;
out:
    if (unlikely(NULL != auth))
        authenticated_put(auth);
    return ret;
}

static int32 access_hook_func(struct sk_buff *skb)
{
    if (TRUE == is_bypass(skb))
        return ND_ACCEPT;
    if (ND_ACCEPT == whitelist_uplink_skb_check(skb))
        return ND_ACCEPT;
    if (ND_ACCEPT != blacklist_uplink_skb_check(skb))
        return ND_DROP;
    if (ND_ACCEPT != authenticated_uplink_skb_check(skb))
        return ND_DROP;
    return ND_ACCEPT;
}

static struct nd_hook_ops access_nd_hook_ops = {
    .priority = 1,
    .hook = access_hook_func
};

static inline BOOL is_from_local(struct sk_buff *skb)
{
    BOOL ret = FALSE;
    const struct iphdr *iph = ip_hdr(skb);
    struct in_device *in_dev = in_dev_get(skb->dev);
    if (unlikely(NULL == in_dev))
    {
        DB_ERR("in_dev is NULL.");
        ret = TRUE;
    }
    else
    {
        struct in_ifaddr *ifa;
        for (ifa = in_dev->ifa_list; NULL != ifa; ifa = ifa->ifa_next)
        {
            if (ifa->ifa_address == iph->saddr)
            {
                ret = TRUE;
                break;
            }
        }
        in_dev_put(in_dev);
    }
    return ret;
}

static inline BOOL is_outer_bypass(struct sk_buff *skb)
{
    const struct iphdr *iph = ip_hdr(skb);

    if (skb_to_vlan_dev(skb))
    {
        if (!portal_vlan_exist(vlan_dev_vlan_id(skb->dev))
            && !portal_interface_exist(skb->dev->name))
            return TRUE;
    }
    else
    {
        if (!portal_interface_exist(skb->dev->name))
            return TRUE;
    }
    if (IPPROTO_ICMP == iph->protocol)
        return TRUE;
    if (IPPROTO_UDP == iph->protocol)
    {
        struct udphdr *udph = (struct udphdr *)((uint8 *)iph + (iph->ihl * 4));
        if (DNS_PORT == ntohs(udph->source)
            || DHCP_SERVER_PORT == ntohs(udph->source)
            || DHCP_CLIENT_PORT == ntohs(udph->source))
            return TRUE;
    }
    return is_from_local(skb);
}

static int32 whitelist_downlink_skb_check(struct sk_buff *skb,
                                          const uint8 *hw_dest)
{
    int32 ret = ND_DROP;
    whitelist_t *white = NULL;

    white = whitelist_search(hw_dest);
    if (NULL != white)
    {
        whitelist_downlink_update(white);
        ret = ND_ACCEPT;
        DB_INF("User \""MACSTR"\" in whitelist.", MAC2STR(hw_dest));
        LOGGING_INFO("User \""MACSTR"\" in whitelist from outside.", MAC2STR(hw_dest));
        whitelist_put(white);
    }
    return ret;
}

static int32 blacklist_downlink_skb_check(struct sk_buff *skb,
                                          const uint8 *hw_dest)
{
    int32 ret = ND_ACCEPT;
    blacklist_t *black = NULL;

    black = blacklist_search(hw_dest);
    if (NULL != black)
    {
        blacklist_downlink_update(black);
        ret = ND_DROP;
        DB_INF("User \""MACSTR"\" in blacklist.", MAC2STR(hw_dest));
        LOGGING_INFO("User \""MACSTR"\" in blacklist from outside.", MAC2STR(hw_dest));
        blacklist_put(black);
    }
    return ret;
}

static int32 authenticated_downlink_skb_check(struct sk_buff *skb,
                                              const uint8 *hw_dest)
{
    int32 ret = ND_DROP;
    authenticated_t *auth = NULL;

    auth = authenticated_search(hw_dest);
    if (unlikely(NULL == auth))
        goto out;
    else
    {
        if (unlikely(0 != authenticated_downlink_skb_update(auth, skb)))
        {
            DB_WAR("authenticated_downlink_skb_update() checked, and drop it.");
            goto out;
        }
    }
    ret = ND_ACCEPT;
out:
    if (unlikely(NULL != auth))
        authenticated_put(auth);
    return ret;
}

static uint32 access_hook_post_routing_hook(uint32 hooknum,
					                        struct sk_buff *skb,
					                        const struct net_device *in,
					                        const struct net_device *out,
					                        int32 (*okfn)(struct sk_buff *))
{
    uint8 hw_dest[HWADDR_SIZE];
    int32 ret;
    if (TRUE == is_outer_bypass(skb))
        return NF_ACCEPT;
    ret = arp_find(hw_dest, skb);
    if (0 != ret)
    {
        const struct iphdr *iph = ip_hdr(skb);
        DB_ERR("Not find nexthop. iph->daddr["IPSTR"].", IP2STR(iph->daddr));
        return NF_DROP;
    }
    if (ND_ACCEPT == whitelist_downlink_skb_check(skb, hw_dest))
        return ND_ACCEPT;
    if (ND_ACCEPT != blacklist_downlink_skb_check(skb, hw_dest))
        return ND_DROP;
    if (ND_ACCEPT != authenticated_downlink_skb_check(skb, hw_dest))
        return ND_DROP;
    return ND_ACCEPT;
}

static struct nf_hook_ops access_nf_post_routing_hook_ops = {
    .hook       = access_hook_post_routing_hook,
    .owner      = THIS_MODULE,
    .pf         = NFPROTO_IPV4,
    .hooknum    = NF_INET_POST_ROUTING,
    .priority   = NF_IP_PRI_FIRST,
};

static int32 __init access_module_init(void)
{
    if (0 != config_init())
    {
        DB_ERR("Config init fail.");
        goto err;
    }
    if (0 != advertising_init(ads_maxcount_push, ads_maxcount_embed))
    {
        DB_ERR("Advertising init fail!!");
        goto err;
    }
    if (0 != blacklist_init(blacklist_maxcount))
    {
        DB_ERR("BlackList init fail!!");
        goto err;
    }
    if (0 != whitelist_init(whitelist_maxcount))
    {
        DB_ERR("WhiteList init fail!!");
        goto err;
    }
    if (0 != authenticated_init(auth_maxcount))
    {
        DB_ERR("Authenticated User init fail!!");
        goto err;
    }
    if (0 != portal_init())
    {
        DB_ERR("Portal init fail!!");
        goto err;
    }
    if (0 != nd_register_hook(&access_nd_hook_ops))
    {
        DB_ERR("NetDevice hook register fail!!");
        goto err;
    }
    if (0 != nf_register_hook(&access_nf_post_routing_hook_ops))
    {
        DB_ERR("NetFilter post-routing hook register fail!!");
        goto err;
    }
    proc_access_service_init();
    DB_INF("Access-Service Module init successfully.");
    LOGGING_INFO("Access-Service Module init successfully.");
    return 0;
err:
    nf_unregister_hook(&access_nf_post_routing_hook_ops);
    nd_unregister_hook(&access_nd_hook_ops);
    portal_destroy();
    authenticated_destroy();
    whitelist_destroy();
    blacklist_destroy();
    advertising_destroy();
    config_final();
    DB_ERR("Access-Service Module init fail!!");
    LOGGING_ERR("Access-Service Module init fail!!");
    return -1;
}

static void __exit access_module_exit(void)
{
    proc_access_service_destroy();
    nf_unregister_hook(&access_nf_post_routing_hook_ops);
    nd_unregister_hook(&access_nd_hook_ops);
    portal_destroy();
    authenticated_destroy();
    whitelist_destroy();
    blacklist_destroy();
    advertising_destroy();
    config_final();
    DB_INF("Access-Service Module remove successfully.");
    LOGGING_INFO("Access-Service Module remove successfully.");
}

module_init(access_module_init);
module_exit(access_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zxc");
MODULE_DESCRIPTION("This module is a Access-Service Module between L2 and L3.");
