/****************************************
* Author: zhangwj
* Date: 2017-01-19
* Filename: netlink_test.c
* Descript: netlink of kernel
* Kernel: 3.10.0-327.22.2.el7.x86_64
* Warning:
******************************************/

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/kthread.h> 
#include <linux/wait.h>
#include <linux/spinlock.h>
#include <net/ip.h>

#include "message.h"
#include "queue.h"

struct nf_hook_ops url_catch_hook;
static struct task_struct *tsk = NULL; 
static queue_head_t *pkt_queue = NULL; 
static queue_head_t *redirect_queue = NULL; 

static spinlock_t pkt_spinlock;
static spinlock_t redirect_spinlock;
//static wait_queue_head_t waitq;

static inline struct iphdr *http_iphdr(const struct sk_buff *skb)
{
     return (struct iphdr *)(eth_hdr(skb) + 1);
}


static struct sk_buff *http_skb_alloc(const struct sk_buff *skb,
                                      const uint32 size)
{
    uint32 nskb_size;
    struct sk_buff *nskb = NULL;
    nskb_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) + size;
    nskb = alloc_skb(nskb_size, GFP_ATOMIC);
    if (NULL == nskb)
        return NULL;
    skb_put(nskb, nskb_size);
    skb_reset_mac_header(nskb);
   
    skb_pull(nskb, sizeof(struct ethhdr));
    skb_reset_network_header(nskb);
    nskb->dev = skb->dev;
    nskb->protocol = skb->protocol;
    return nskb;
}

static void http_mac_header_fill(struct sk_buff *skb1,
                                 const struct sk_buff *skb2)
{ 
    struct ethhdr *ethh1 = eth_hdr(skb1);
    struct ethhdr *ethh2 = eth_hdr(skb2);
    memcpy(ethh1->h_dest, ethh2->h_source, sizeof(ethh1->h_dest));
    memcpy(ethh1->h_source, ethh2->h_dest, sizeof(ethh1->h_source));
    ethh1->h_proto = ethh2->h_proto;
    
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
    skb_push(skb, sizeof(struct ethhdr));

    //DB_INF("before xmit: skb->users:%d", skb->users);
    ret = dev_queue_xmit(skb);
    //DB_INF("after xmit: skb->users:%d", skb->users);
    if (0 != ret)
    {
        printk("dev_queue_xmit() call fail. errno:%d.", ret);
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
        printk("http_skb_alloc() call fail.");
        return -1;
    }
    http_transport_header_fill(nskb, skb, NULL, 0, FALSE, TRUE, FALSE, FALSE);
    http_network_header_fill(nskb, skb, sizeof(struct tcphdr));
    http_mac_header_fill(nskb, skb);
    ret = http_skb_xmit(nskb);
    if (0 != ret)
        printk("http_skb_xmit() call fail.");
    return ret;
}


int32 policy_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen) 
{
	*olen = 0;
	return 0;
}

int32 redirect_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen) 
{
	
	*olen = 0;
	return 0;
}

static void url_report(struct sk_buff *skb)
{
   struct tcphdr *tcp;
   char *_and;
   char *data;
   int len;

   tcp = tcp_hdr(skb);
   data = (char *)((unsigned long)tcp + (unsigned long)(tcp->doff * 4));

 	if (strncmp(data, "GET ", 4) == 0 && strstr(data, ".mp4") != NULL) {
//		_and = strstr(data, "\r\n\r\n");
//		len = _and - data;
//		msg_send_no_reply(MSG_CMD_VIDEO_CACHE_URL, data, len);
		queue_item_t *item = (queue_item_t *)kmalloc(sizeof(queue_item_t), GFP_ATOMIC);
		item->skb = skb_get(skb);
		spin_lock(&pkt_spinlock);
		queue_enqueue(pkt_queue, item);
		spin_unlock(&pkt_spinlock);
		if (NULL != tsk && TASK_RUNNING != tsk->state)
            wake_up_process(tsk);
 	} 
	return;

}


static unsigned int url_catch(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in,
					const struct net_device *out, int (*okfn)(struct sk_buff *))
{
   struct sk_buff *sb = skb;
   struct tcphdr *tcp;
   struct iphdr *ip = ip_hdr(sb);
   /* Make sure this is a TCP packet first */
   if (ip->protocol != IPPROTO_TCP || ip->tot_len < 80)
     return NF_ACCEPT;             /* Nope, not TCP */
   tcp = (struct tcphdr *)((sb->data) + (ip_hdr(sb)->ihl * 4));
   
   /* Now check to see if it's an FTP packet */
   if (tcp->dest != htons(80))
     return NF_ACCEPT;             /* Nope, not FTP */

   url_report(sb);

   /* We are finished with the packet, let it go on its way */
   return NF_ACCEPT;
}

static int thread_function(void *data)	
{  
	queue_item_t *qitem = NULL;
	do {  
		spin_lock_bh(&pkt_spinlock);
		if (TRUE == queue_empty(pkt_queue)) {
			spin_unlock_bh(&pkt_spinlock);
//			DECLARE_WAITQUEUE(current_wait, current);
//			add_wait_queue(&waitq, &current_wait);
			__set_current_state(TASK_INTERRUPTIBLE);
			schedule();
//			remove_wait_queue(&waitq, &current_wait);
			continue;	
		} 
		qitem = queue_dequeue(pkt_queue);
		spin_unlock_bh(&pkt_spinlock);
		struct tcphdr *tcp;
		char *_and;
		char *data;
		int len;
		tcp = tcp_hdr(qitem->skb);
		data = (char *)((unsigned long)tcp + (unsigned long)(tcp->doff * 4));
		_and = strstr(data, "\r\n\r\n");
		len = _and - data;
		char *rcv_buf;
		int rcv_len = 0;
		if (msg_send_syn(MSG_CMD_VIDEO_CACHE_URL, data, len, &rcv_buf, &rcv_len) == 0) {
			printk("have get redirect url %s\n", rcv_buf);
			int32 ret;
		    struct sk_buff *nskb = NULL;
		    int8 http_data[1500];
		    uint32 http_dlen = 0;
		    struct iphdr *iph = NULL;
		    ret = http_ack_reply(qitem->skb);
		    if (0 != ret) {
		        printk("http_ack_reply() call fail.");
		        goto out;
		    }
		    iph = http_iphdr(qitem->skb);
		    
	        struct ethhdr *ethh = eth_hdr(qitem->skb);
	        http_dlen = sprintf(http_data,
	                           "HTTP/1.1 302 Found\r\n"
	                           "Location: %s\r\n"
	                           "Content-Type: text/plain\r\n"
	                           "Connection: close\r\n"
	                           "Server: Apache-Coyote/1.1\r\n"
	                           "Content-Length: 0\r\n"
	                           "\r\n",
	                           rcv_buf
	                           );
		    
		    nskb = http_skb_alloc(qitem->skb, http_dlen);
		    if (NULL == nskb) {
		        printk("http_skb_alloc() call fail.");
		       
		        goto out;
		    }
		    http_transport_header_fill(nskb, qitem->skb, http_data, http_dlen, FALSE, TRUE, TRUE, FALSE);
		    http_network_header_fill(nskb, qitem->skb, sizeof(struct tcphdr) + http_dlen);
		    http_mac_header_fill(nskb, qitem->skb);
		    ret = http_skb_xmit(nskb);
		    if (0 != ret) 
		        printk("http_skb_xmit() call fail.");
			else 
				printk("http_redirect sucesssssssssssssssssssss\n");
out:
			free_rcv_buf(rcv_buf);
		}

		kfree_skb(qitem->skb);
		kfree(qitem);
	}while(!kthread_should_stop());  
	return 0;  
} 

static int __init vc_init(void)
{
    msg_cmd_register(MSG_CMD_VC_POLICY, policy_handler);
//	msg_cmd_register(MSG_CMD_VC_REDIRECT, redirect_handler);
	pkt_queue = kmalloc(sizeof(queue_head_t), GFP_KERNEL);
	queue_init(pkt_queue);
	queue_init(redirect_queue);
	spin_lock_init(&pkt_spinlock);
	spin_lock_init(&redirect_spinlock);
	url_catch_hook.hook     = url_catch;
	url_catch_hook.pf       = PF_INET;
	url_catch_hook.priority = NF_IP_PRI_FIRST;
	url_catch_hook.hooknum  = NF_INET_FORWARD;
	nf_register_hook(&url_catch_hook);
//	init_waitqueue_head(&waitq);
	tsk = kthread_run(thread_function, NULL, "mythread%d", 1); 
	if (IS_ERR(tsk)) {  
        printk(KERN_INFO "create kthread failed!\n");  
    }  
    else {  
        printk(KERN_INFO "create ktrhead ok!\n");  
    }  
    return 0;
}

static void __exit vc_exit(void)
{
	msg_cmd_unregister(MSG_CMD_VC_POLICY);
	nf_unregister_hook(&url_catch_hook);
	if (!IS_ERR(tsk)){  
        int ret = kthread_stop(tsk);  
        printk(KERN_INFO "thread function has run %ds\n", ret);  
    }
	kfree(pkt_queue);
}

module_init(vc_init);
module_exit(vc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("zc");
