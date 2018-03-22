/****************************************
* Author: zhangwj
* Date: 2017-01-19
* Filename: netlink_test.c
* Descript: netlink of kernel
* Kernel: 3.10.0-327.22.2.el7.x86_64
* Warning:
******************************************/

#include <linux/init.h>
#include <linux/module.h>
#include <linux/types.h>
#include <net/sock.h>
#include <linux/netlink.h>
#include <linux/kthread.h> 
#include <linux/wait.h>
#include <asm/param.h>
#include "message.h"

#define MSG_LEN         (8192-sizeof(struct nlmsghdr))


MODULE_LICENSE("GPL");
MODULE_AUTHOR("zhoucong");
MODULE_DESCRIPTION("netlink example");


static struct sock *event_sock = NULL;
static struct sock *umsg_sock = NULL;

extern struct net init_net;
static struct mutex event_mutex;
static struct mutex umsg_mutex;
static struct mutex cmd_list_mutex;
//static struct mutex wait_list_mutex;
static spinlock_t wait_list_lock;
atomic_t v = ATOMIC_INIT(0);


typedef struct msg_module_cmd_st{
	struct list_head list;	/*已注册命令的链表*/
	int32 cmd;				/*命令*/
	msg_cmd_handle_cb func; /*命令的回调函数*/
}msg_module_cmd_t;
static LIST_HEAD(wait_queue_list);

typedef struct kernel_module_st{
	struct list_head list;
	int32 module_id;
	wait_queue_head_t waitq;
	struct sk_buff *rcv_skb;
	int condition;
}kmodule;

typedef struct task_queue_st{
	struct list_head list;
	int32 sn;
	wait_queue_head_t waitq;
	struct sk_buff *rcv_skb;
}task_queue;

static LIST_HEAD(cmd_call_func);    /*调用各模块回调*/
/*根据命令获取msg_module_cmd_t*/
static msg_module_cmd_t *msg_get_cmdfunc(const int32 cmd)
{
	msg_module_cmd_t *msg_cmd = NULL;
	list_for_each_entry(msg_cmd, &cmd_call_func, list) {
		if ( msg_cmd->cmd == cmd )
			return msg_cmd;
	}
	return NULL;
}

static task_queue *get_task_queue(int sn)
{
	task_queue *tq = NULL;
	list_for_each_entry(tq, &wait_queue_list, list) {
		if ( tq->sn == sn )
			return tq;
	}
	return NULL;
}


int32 free_rcv_buf(void *rcv_buf)
{
	struct sk_buff *skb = NULL;
	if (!rcv_buf)
		return -1;
	skb = *(struct sk_buff **)(rcv_buf-sizeof(void *));
	kfree_skb(skb);
	return 0;
}




/*本模块的命令注册*/
int32 msg_cmd_register(const int32 cmd,
                       msg_cmd_handle_cb cb)
{
	msg_module_cmd_t *msg_cmd = NULL;
	if (msg_get_cmdfunc(cmd))
		return -1;
	msg_cmd = (msg_module_cmd_t *)kmalloc(sizeof(msg_module_cmd_t), GFP_KERNEL);
	msg_cmd->cmd = cmd;
	msg_cmd->func = cb;
	mutex_lock(&cmd_list_mutex);
	list_add(&(msg_cmd->list), &cmd_call_func);
	mutex_unlock(&cmd_list_mutex);
	return 0;
}

/*命令注销*/
int32 msg_cmd_unregister(const int32 cmd)
{
	msg_module_cmd_t* p = NULL;
	msg_module_cmd_t* next = NULL;
	mutex_lock(&cmd_list_mutex);
	list_for_each_entry_safe(p, next, &cmd_call_func, list) {
		if ( p->cmd == cmd ) {
			list_del(&p->list);
			kfree(p);
			break;
		}
	}
	mutex_unlock(&cmd_list_mutex);
	return 0;
}

/*
int32 msg_kmodule_register(int16 mid)
{
	kmodule *km = (kmodule *)kmalloc(sizeof(kmodule), GFP_KERNEL);
	km->module_id = mid;
	km->rcv_skb = NULL;
	km->condition = 0;
	init_waitqueue_head(&km->waitq);
	mutex_lock(&module_list_mutex);
	list_add(&km->list, &kernel_module_list);
	mutex_unlock(&module_list_mutex);
}

int32 msg_kmodule_unregister(int16 mid)
{
	kmodule *p = NULL;
	kmodule *next = NULL;
	mutex_lock(&module_list_mutex);
	list_for_each_entry_safe(p, next, &kernel_module_list, list) {
		if ( p->module_id == mid ) {
			list_del(&p->list);
			kfree(p);
			break;
		}
	}
	mutex_unlock(&module_list_mutex);
}
*/

static void umsg_rcv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    msg_t *rcv_msg = NULL;	
	msg_t *snd_msg = NULL;
	msg_module_cmd_t *msg_cmd = NULL;
	int olen = 0;
	
	if (skb->len >= nlmsg_total_size(sizeof(msg_t))) {
		struct sk_buff *out_skb = nlmsg_new(MSG_LEN, GFP_KERNEL);
		if (!out_skb) {
			printk("umsg kernel alloc error\n");
			return;
		}
        nlh = nlmsg_hdr(skb);
        rcv_msg = NLMSG_DATA(nlh);
		snd_msg = NLMSG_DATA(nlmsg_hdr(out_skb));
		olen = MSG_LEN - sizeof(msg_t);
		msg_cmd = msg_get_cmdfunc(rcv_msg->cmd);
		if (!msg_cmd) {
			snd_msg->dlen = 0;
			snd_msg->cmd = rcv_msg->cmd;
			snd_msg->result = ERR_CODE_NONECMD;
			olen = 0;
		} else {
			snd_msg->result = msg_cmd->func(rcv_msg->cmd, rcv_msg->data, rcv_msg->dlen, snd_msg->data, &olen);
			snd_msg->cmd = rcv_msg->cmd;
			snd_msg->dlen = olen;
		}
		nlmsg_put(out_skb, 0, 0, NLMSG_DONE, olen + sizeof(msg_t), 0);
//		printk("send size = %d", nlmsg_hdr(out_skb)->nlmsg_len);
//		mutex_lock(&umsg_mutex);
		nlmsg_unicast(umsg_sock, out_skb, nlh->nlmsg_pid);
//		mutex_unlock(&umsg_mutex);
	}
	
}

static void event_rcv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
	msg_t *rcv_msg = NULL;
	task_queue *tq = NULL;

    if(skb->len >= nlmsg_total_size(sizeof(msg_t)))
    {
        nlh = nlmsg_hdr(skb);
        rcv_msg = NLMSG_DATA(nlh);
		spin_lock(&wait_list_lock);
		tq = get_task_queue(rcv_msg->sn);
		if (tq) {
			tq->rcv_skb = skb_get(skb);	
			wake_up_interruptible(&tq->waitq);
		}	
		spin_unlock(&wait_list_lock);
    }
}


struct netlink_kernel_cfg event_cfg = { 
        .input  = event_rcv_msg, /* set recv callback */
		.cb_mutex = &event_mutex,
		
};  
		
		

struct netlink_kernel_cfg umsg_cfg = { 
        .input  = umsg_rcv_msg, /* set recv callback */
		.cb_mutex = &umsg_mutex,
		
};

int msg_send_syn(int32 cmd, void *sbuf, int slen, void **obuf, int *olen)
{
	struct sk_buff *nl_skb = NULL;
    struct nlmsghdr *nlh = NULL;
	msg_t *msg = NULL;
	msg_t *rcv_msg = NULL;
	task_queue *tq = NULL;
    int ret = -1, len = 0, grp = 0;
	msg_t *snd_msg = NULL;
	int msg_len = 0;
	if (MODULE_TYPE_GET(cmd) == KERNEL_MODULE) {
		msg_module_cmd_t *msg_cmd = msg_get_cmdfunc(cmd);
		if (!msg_cmd) {
			ret = ERR_CODE_NONECMD;
		} else {

			struct sk_buff *out_skb = nlmsg_new(MSG_LEN, GFP_KERNEL);
			if (!out_skb) {
				printk("out_skb kernel alloc error\n");
				return ret;
			}
			snd_msg = NLMSG_DATA(nlmsg_hdr(out_skb));
			int rcv_len = MSG_LEN - sizeof(msg_t);
			ret = msg_cmd->func(cmd, sbuf, slen, snd_msg->data, &rcv_len);
			if (ret == 0) {
				*obuf = snd_msg->data;
				*olen = rcv_len;
				*(struct sk_buff **)(*obuf-sizeof(void *)) = out_skb;
			}
		}
		return ret;	

	}

	
	msg_len = sizeof(msg_t) + slen;
	if (msg_len > MSG_LEN)
		goto out;
    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(msg_len, GFP_KERNEL);
    if(!nl_skb) {
        printk("netlink alloc failure\n");
        goto out;
    }

    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, NLMSG_DONE, msg_len, 0);
    if(nlh == NULL) {
        printk("nlmsg_put failaure \n");
        goto out;
    }

    /* 拷贝数据发送 */
	msg = nlmsg_data(nlh);
	msg->cmd = cmd;
	msg->dlen = slen;
	msg->result = 0;
	msg->sn = atomic_inc_return(&v);
	tq = kmalloc(sizeof(task_queue), GFP_KERNEL);
	if(!tq) {
		goto out;
	}
	tq->sn = msg->sn;
	tq->rcv_skb = NULL;
	init_waitqueue_head(&tq->waitq);
	spin_lock_bh(&wait_list_lock);
	list_add_tail(&tq->list, &wait_queue_list);
	spin_unlock_bh(&wait_list_lock);
	
    memcpy(nlmsg_data(nlh) + sizeof(msg_t), sbuf, slen);
	grp = MODULE_GET(cmd);
	DECLARE_WAITQUEUE(wait, current);
	add_wait_queue(&tq->waitq, &wait);
//	mutex_lock(&event_mutex);
	len = nlmsg_multicast(event_sock, nl_skb, 0, grp, MSG_DONTWAIT);
//	mutex_unlock(&event_mutex);
	nl_skb = NULL;
	if (len < 0) {
//		printk(KERN_INFO "Error while sending bak to user, err id: %d\n", ret);	
		goto out;
	}
	__set_current_state(TASK_INTERRUPTIBLE);
	schedule_timeout(1*HZ);
	
	__set_current_state(TASK_RUNNING);

	if (tq->rcv_skb != NULL) {
		rcv_msg = NLMSG_DATA(nlmsg_hdr(tq->rcv_skb));
		ret = rcv_msg->result;
		if (rcv_msg->result == 0 && obuf != NULL && olen != NULL && rcv_msg->dlen != 0) {			
			*obuf = rcv_msg->data;
			*olen = rcv_msg->dlen;
			*(struct sk_buff **)(*obuf-sizeof(void *)) = tq->rcv_skb;		
		} 
	}
out:
	if (ret != 0 || obuf == NULL || olen == NULL || (rcv_msg && rcv_msg->dlen == 0)) {
		if (tq && tq->rcv_skb)
			kfree_skb(tq->rcv_skb);
		if (obuf)
			*obuf = NULL;
		if (olen)
			*olen = 0;
	}
	if (tq) {
		spin_lock_bh(&wait_list_lock);
		list_del(&tq->list);
		remove_wait_queue(&tq->waitq, &wait);
		kfree(tq);
		tq = NULL;
		spin_unlock_bh(&wait_list_lock);
	}
	if (nl_skb) 
		nlmsg_free(nl_skb);
	return ret;
}

int test_netlink_init(void)
{
    /* create netlink socket */
    event_sock = (struct sock *)netlink_kernel_create(&init_net, NETLINK_EVENT, &event_cfg);
    if(event_sock == NULL)
    {   
        printk("netlink_kernel_create error !\n");
        return -1; 
    }   

	umsg_sock = (struct sock *)netlink_kernel_create(&init_net, NETLINK_UMSG, &umsg_cfg);
    if(umsg_sock == NULL)
    {   
        printk("netlink_kernel_create error !\n");
        return -1; 
    }   
	
	mutex_init(&cmd_list_mutex);
	spin_lock_init(&wait_list_lock);
		
    return 0;
}

void test_netlink_exit(void)
{
	
    if (event_sock){
        netlink_kernel_release(event_sock); /* release ..*/
        event_sock = NULL;
    }  
	if (umsg_sock){
        netlink_kernel_release(umsg_sock); /* release ..*/
        umsg_sock = NULL;
    }  

	mutex_destroy(&cmd_list_mutex);

    printk("test_netlink_exit!\n");
}

EXPORT_SYMBOL(msg_send_syn);
EXPORT_SYMBOL(msg_cmd_register);
EXPORT_SYMBOL(msg_cmd_unregister);
EXPORT_SYMBOL(free_rcv_buf);


module_init(test_netlink_init);
module_exit(test_netlink_exit);

