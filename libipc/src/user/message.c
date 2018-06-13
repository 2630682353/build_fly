#include "message.h"
#include <stdio.h>
#include <stdlib.h>
#include "memory_pool.h"
#include "thread_pool.h"
#include "queue.h"
#include "type.h"
#include "debug.h"
#include <errno.h>
#include "sock.h"


#define BUF_POOL_UNITSIZE 8192
#define BUF_POOL_INITNUM 20
#define BUF_POOL_GROWNUM 16
#define ITEM_POOL_UNITSIZE sizeof(queue_item_t)
#define ITEM_POOL_INITNUM 10
#define ITEM_POOL_GROWNUM 8
#define PKT_POOL_UNITSIZE sizeof(msg_pkt_t)
#define PKT_POOL_INITNUM 10
#define PKT_POOL_GROWNUM 8
#define THREAD_NUM  3

static int16 s_module_id = 0;
static int16 msg_sn = 0;
static pthread_mutex_t sn_mutex;

/*数据包信息结构体,用在queue_item_t的arg中传递收/发的数据包*/
typedef struct msg_pkt_st{
    sock_addr_u paddr;  /*peer address information*/
    int16       dmid;   /*destination module id, equal to peer module id*/
    int16       smid;   /*source module id, equal to self module id*/
    buffer_t    in;     /*received packet buffer*/
    buffer_t    out;    /*send packet buffer*/
}msg_pkt_t;

/*typedef struct msg_pkt_queue_st{
    queue_head_t    queue;
    pthread_mutex_t mutex;
}msg_pkt_queue_t;
*/
typedef struct msg_dst_cmd{
	int32 cmd;
	struct list_head cmd_list;	/*对端模块的命令列表*/
}msg_dst_cmd_t;



typedef struct msg_module_st{
	struct list_head list;		/*已注册对端模块的链表*/
	int32 mid;					/*对端模块ID*/
	sock_addr_u addr;
	struct list_head cmd_list;	/*对端模块的命令列表*/
}msg_module_t;

typedef struct msg_module_cmd_st{
	struct list_head list;	/*已注册命令的链表*/
	int32 cmd;				/*命令*/
	msg_cmd_handle_cb func; /*命令的回调函数*/
}msg_module_cmd_t;


static queue_head_t *sp_rcv_queue = NULL;    /*收包队列,队列中存储的都是待处理的数据*/
static queue_head_t *sp_snd_queue = NULL;    /*发包队列,队列中存储的都是待发送的数据*/
static thread_pool_t *sp_handle_pool = NULL;    /*业务处理线程池*/
static socket_t *sp_rcv_sock = NULL;    /*收包sock*/
static socket_t *sp_snd_sock = NULL;    /*发包sock*/


static mempool_t *mempool_buf = NULL;  /*数据内存池*/
static mempool_t *mempool_queue_item = NULL;  /*队列元素内存池*/
static mempool_t *mempool_pkt = NULL;  /*数据包内存池*/

static pthread_cond_t snd_thread_cond; /*发送线程条件变量*/

static socket_t *sp_nlk_rcv_sock = NULL;
static socket_t *sp_nlk_snd_sock = NULL;




//static queue_head_t *sp_idle_queue = NULL;  /*闲包队列,队列中存储的都是待接收数据的包*/

static pthread_t pt_snd = 0;
static pthread_t pt_rcv = 0;

static LIST_HEAD(s_dst_modules);    /*通信对端模块信息*/
static LIST_HEAD(s_self_cmds);    /*本模块注册的命令*/


static void *msg_rcv_thread_cb(void *arg);
static void *msg_snd_thread_cb(void *arg);
static msg_module_cmd_t *msg_get_cmdfunc(const int32 cmd);





int32 msg_init(const int16 module_id  /*本模块的模块ID*/
						)		
{
    /*1. 初始化收/发包队列*/
    /*2. 创建收包线程*/
    /*3. 创建发包线程*/
    /*4. 创建业务处理线程池,后续用于多业务的并发处理*/
    /*5. 初始化收包socket*/
    /*6. 初始化发包socket*/

	char rcv_path[20] = {0};
	char snd_path[20] = {0};
	s_module_id = module_id;
	msg_sn = 0;
	pthread_mutex_init(&sn_mutex, NULL);
	
	DB_INF("init sp_rcv_queue");
	sp_rcv_queue = malloc(sizeof(queue_head_t));
	pthread_mutex_init(&sp_rcv_queue->mutex, NULL);
	queue_init(sp_rcv_queue);

	DB_INF("init sp_snd_queue");
	sp_snd_queue = malloc(sizeof(queue_head_t));
	pthread_mutex_init(&sp_snd_queue->mutex, NULL);
	queue_init(sp_snd_queue);
	
	sp_handle_pool = thread_pool_create(THREAD_NUM);
	DB_INF("after init thread_pool");

	snprintf(rcv_path, sizeof(rcv_path) - 1, "/tmp/%d_rcv", module_id);
	snprintf(snd_path, sizeof(snd_path) - 1, "/tmp/%d_snd", module_id);
	sp_rcv_sock = unix_sock_init(rcv_path);
	sp_snd_sock = unix_sock_init(snd_path);
	
	if(sp_rcv_sock->fd < 1)
		return -1;

	DB_INF("before init mem_pool");
	mempool_buf = memory_pool_init(BUF_POOL_UNITSIZE, BUF_POOL_INITNUM, BUF_POOL_GROWNUM);
	mempool_queue_item = memory_pool_init(ITEM_POOL_UNITSIZE, ITEM_POOL_INITNUM, ITEM_POOL_GROWNUM);
	mempool_pkt = memory_pool_init(PKT_POOL_UNITSIZE, PKT_POOL_INITNUM, PKT_POOL_GROWNUM);
	DB_INF("after init mem_pool");

	pthread_cond_init(&snd_thread_cond, NULL);
	
	int grp = (1 << (module_id - 1));
	sp_nlk_rcv_sock = netlink_sock_init(NETLINK_EVENT, grp, 0);
	sp_nlk_snd_sock = netlink_sock_init(NETLINK_EVENT, grp, 0);

	pthread_create(&pt_snd, NULL, (void *)msg_snd_thread_cb, NULL);
	pthread_create(&pt_rcv, NULL, (void *)msg_rcv_thread_cb, NULL);
	
}




void msg_final(void)
{
    /*1. 销毁收包socket*/
    /*2. 销毁收包线程*/
    /*3. 销毁业务线程池*/
    /*4. 销毁发包线程*/
    /*5. 销毁发包socket*/
    /*6. 销毁收/发包队列*/

	pthread_mutex_destroy(&sn_mutex);
	pthread_cancel(pt_rcv);
	pthread_join(pt_rcv, NULL);
	sock_delete(sp_rcv_sock);
	sock_delete(sp_nlk_rcv_sock);
	thread_pool_destroy(sp_handle_pool);
	pthread_cancel(pt_snd);
	pthread_join(pt_snd, NULL);
	sock_delete(sp_snd_sock);
	sock_delete(sp_nlk_snd_sock);

	queue_item_t *item = NULL;
	msg_pkt_t *pkt = NULL;
	queue_destroy(sp_rcv_queue);
    while (FALSE == queue_empty(sp_rcv_queue))
    {
        item = queue_dequeue(sp_rcv_queue);
		pkt = (msg_pkt_t *)(item->arg);
		mem_free(pkt->in.buf);
		mem_free(pkt->out.buf);
        free(item->arg);
        free(item);
    }
	pthread_mutex_destroy(&sp_rcv_queue->mutex);
	free(sp_rcv_queue);
	
	queue_destroy(sp_snd_queue);
    while (FALSE == queue_empty(sp_snd_queue))
    {
        item = queue_dequeue(sp_snd_queue);
		pkt = (msg_pkt_t *)(item->arg);
		mem_free(pkt->in.buf);
		mem_free(pkt->out.buf);
        free(item->arg);
        free(item);
    }
	pthread_mutex_destroy(&sp_snd_queue->mutex);
	free(sp_snd_queue);
	memory_pool_destroy(mempool_buf);
	memory_pool_destroy(mempool_queue_item);
	memory_pool_destroy(mempool_pkt);
	msg_dst_module_unregister(-1);
	msg_cmd_unregister_all();
	
}

/*请求消息发送接口*/
int32 msg_send_syn(
       			   int32 cmd,   /*命令*/
                   void *sbuf,  /*发包buffer*/
                   int32 slen,  /*sbuf中数据长度*/
                   void **rbuf, /*收包buffer*/
                   int32 *rlen) /*入参为rbuf的存储空间总大小,返回rbuf中实际收到的数据的长度*/
{
    /*1. 根据命令字判定命令字要发往的模块,再根据模块取出其对应的模块地址*/
    /*2. 组织消息报文头,客户端维护一个序列号,每发一个包序列号+1*/
    /*3. 通过发包sock发送消息到对应的模块*/
    /*4. 等待收取消息的应答,必须引入超时机制,避免对端因为进程崩溃造成无法收到应答消息,超时时间定死为1秒*/
    /*5. 如果请求消息超时未收到应答,则返回发送消息失败*/
    /*6. 如果收到了应答消息,则:
     *  6.1. 检查应答消息的合法性;
     *  6.2. 将应答报文中的消息数据拷贝到rbuf中,并设置rlen的值;
     *  6.3. 返回应答消息中的错误码.
     */
    msg_t *snd_msg = NULL;
	socket_t *temp_sock = NULL;
	msg_t *rcv_msg = NULL;
	int ret = -1, temp_fd = 0;
	int8 *rcv_buf = NULL;
	int dmid = MODULE_GET(cmd);
    if ((slen + sizeof(msg_t)) > mempool_buf->unitsize)
		goto out;
    msg_module_t* p_module = NULL;
	msg_dst_cmd_t* p_cmd = NULL;
	sock_addr_u *addr = NULL;
	list_for_each_entry(p_module, &s_dst_modules, list) {
		if ( p_module->mid == dmid ) {
			addr = &p_module->addr;
			break;
		}
	}
	if (!addr) {
		DB_ERR("dst addr null");
		goto out;
	}
	
	snd_msg = (msg_t*)mem_alloc(mempool_buf);
	snd_msg->cmd = cmd;
	snd_msg->dmid = dmid;
	snd_msg->dlen = slen;
	
	int len = 0;
	
	if (MODULE_TYPE_GET(cmd) == USER_MODULE) {	
		char file_temp[20] = {0};
		strcpy(file_temp, "/tmp/test.XXXXXX");
		if ((temp_fd = mkstemp(file_temp)) < 0) {
		    DB_ERR("mktemp error");
			goto out;
		}
		temp_sock = unix_sock_init(file_temp);
		DB_INF("unix_sendmsg");
		if (!temp_sock)
			goto out;
		len = sock_sendmsg_unix(temp_sock, snd_msg, sizeof(msg_t), sbuf, slen, addr);

	} else {
		int temp_sn = 0;
		pthread_mutex_lock(&sn_mutex);
		temp_sn = (s_module_id<<16) + msg_sn;
		msg_sn++;
		pthread_mutex_unlock(&sn_mutex);
		temp_sock = netlink_sock_init(NETLINK_UMSG, 0, temp_sn);
		DB_INF("netlink_sendmsg");
		if (!temp_sock)
			goto out;
		len = sock_sendmsg_netlink(temp_sock, snd_msg, sizeof(msg_t), sbuf, slen, addr);
		
	}
	
//	len = sock_sendto(temp_sock, snd_msg, sizeof(msg_t) + slen, addr);
	if (len <= 0)
		goto out;

//	DB_INF("cli have send len:%d", slen);
	rcv_buf = mem_alloc(mempool_buf);
	len = sock_recvfrom(temp_sock, rcv_buf, mempool_buf->unitsize, NULL);
	if (len <= 0)
		goto out;
	if (MODULE_TYPE_GET(cmd) == USER_MODULE)
		rcv_msg = rcv_buf;
	else
		rcv_msg = rcv_buf+sizeof(struct nlmsghdr);
	
	DB_INF("cli have recv %s, len:%d, len2:%d,cmd:%d,res:%d", rcv_msg->data, len, sizeof(msg_t) + rcv_msg->dlen,
									rcv_msg->cmd, rcv_msg->result);
	ret = rcv_msg->result;
	if (rcv_msg->cmd == snd_msg->cmd && rcv_msg->result == 0 
		&& rbuf != NULL && rlen != NULL && rcv_msg->dlen != 0) {
		*rbuf = rcv_msg->data;
		*rlen = rcv_msg->dlen;
	}

out:
	if (temp_fd > 0)
		close(temp_fd);
	if (snd_msg)
		mem_free(snd_msg);
	if (temp_sock) 
		sock_delete(temp_sock);
	if (ret != 0 || rbuf == NULL || rlen == NULL || (rcv_msg && rcv_msg->dlen == 0)) {
		if (rcv_buf)
			mem_free(rcv_buf);
		if (rbuf)
			*rbuf = NULL;
		if (rlen)
			*rlen = 0;
	}
	return ret;
	
}

/*业务处理函数,本接口是在业务线程回调函数中调用的*/
static void msg_handle(queue_item_t *item)
{
    /*1. 数据有效性和合法性检查*/
    /*2. 将pkt->in.buf中的数据强制转换为msg消息*/
    /*3. 判定消息的有效性和合法性*/
    /*4. 根据msg->cmd的不同调用不同的命令的处理函数进行处理
     *  4.1. 如果msg->cmd不能够本模块处理不了,则返回对应的不支持该功能的错误消息
     */
    /*5. 根据命令处理的结果封装应答消息*/
    /*6. 将应答消息加入到pkt->out成员中*/
    /*7. 获取发包队列的锁*/
    /*8. 将pkt入队到发包队列中*/
    /*9. 释放发包队列的锁*/

	msg_pkt_t *pkt = (msg_pkt_t*)(item->arg);
	if (NULL == pkt)
		return;
	msg_t *recv_msg = (msg_t*)(pkt->in.buf + pkt->in.offset);
	pkt->out.size = mempool_buf->unitsize;
	int olen = mempool_buf->unitsize - sizeof(msg_t);
	pkt->out.offset = pkt->in.offset;
	msg_t *snd_msg = ((msg_t*)(pkt->out.buf + pkt->out.offset));
	
	int32 cmd = recv_msg->cmd;
	snd_msg->dmid = recv_msg->smid;
	snd_msg->sn = recv_msg->sn;
	msg_module_cmd_t *msg_cmd = msg_get_cmdfunc(cmd);
	if (!msg_cmd) {
		
		DB_ERR("cmd not registered  %d", cmd);
		snd_msg->dlen = 0;
		snd_msg->result = ERR_CODE_NONECMD;
		snd_msg->cmd = recv_msg->cmd;
		pkt->out.len = pkt->out.offset + sizeof(msg_t);

	} else {
//		DB_INF("before func dlen:%s    %d  thread_id:%ld",recv_msg->data, recv_msg->dlen, pthread_self());
		snd_msg->result = msg_cmd->func(cmd, recv_msg->data, recv_msg->dlen, snd_msg->data, &olen);
//		DB_INF("after func");
		snd_msg->dlen = olen;
		snd_msg->cmd = recv_msg->cmd;
		pkt->out.len = pkt->out.offset + sizeof(msg_t) + olen;
	}
	
	if (pkt->in.offset == sizeof(struct nlmsghdr)) {
		
		struct nlmsghdr *nlh = (struct nlmsghdr *)pkt->out.buf;
		nlh->nlmsg_len = pkt->out.len;
        nlh->nlmsg_flags = 0;
        nlh->nlmsg_type = 0;
        nlh->nlmsg_seq = 0;
        nlh->nlmsg_pid = 0; //self port
	}
	
	pthread_mutex_lock(&sp_snd_queue->mutex);
	queue_enqueue(sp_snd_queue, item);
	pthread_cond_signal(&snd_thread_cond);
	pthread_mutex_unlock(&sp_snd_queue->mutex);
	DB_INF("after msg_handle");
	
}

/*业务线程回调函数*/
static void msg_handle_cb(void *arg)
{
    /*1. 获取收包队列的锁*/
    /*2. 从收包队列中出队第一个msg_pkt_t数据包pkt*/
    /*3. 释放收包队列的锁*/
    /*4. 调用msg_handle()函数,并传入pkt进行业务处理*/
	queue_item_t *item = NULL;
	pthread_mutex_lock(&(sp_rcv_queue->mutex));
	if (FALSE ==  queue_empty(sp_rcv_queue))
		item = queue_dequeue(sp_rcv_queue);
	else {
		pthread_mutex_unlock(&(sp_rcv_queue->mutex));
		return;
	}
	pthread_mutex_unlock(&(sp_rcv_queue->mutex));
	msg_handle(item);
	
	
}

/*发包线程回调函数*/
static void *msg_snd_thread_cb(void *arg)
{
    while (1)
    {
        /*1. 获取发包队列的锁*/
        /*2. 查看发包队列是否为空的
         *  2.1. 如果是空的,则释放发包队列锁,并sleep(1),随后继续从第1步开始轮训;
         *  2.2. 如果不为空,则继续执行第3步*/
        /*3. 从发包队列中出队一个msg_pkt_t的数据包pkt*/
        /*4. 释放发包队列的锁*/
        /*5. 通过socket发送数据包,数据包发送的目的地址信息在pkt的paddr成员中存储着*/
        /*6. 如果线程正在销毁,则退出while(1)的循环*/

		pthread_mutex_lock(&(sp_snd_queue->mutex));
		if (TRUE == queue_empty(sp_snd_queue)) {
			pthread_cond_wait(&snd_thread_cond, &(sp_snd_queue->mutex));
		}

		queue_item_t *item = queue_dequeue(sp_snd_queue);
		pthread_mutex_unlock(&(sp_snd_queue->mutex));
		msg_pkt_t *snd_pkt = (msg_pkt_t*)(item->arg);
		
//		DB_INF("server before sock_sendto: %d", snd_pkt->out.len);
		if (snd_pkt->out.offset == sizeof(struct nlmsghdr)) {
			sock_sendto(sp_nlk_snd_sock, snd_pkt->out.buf, snd_pkt->out.len, &snd_pkt->paddr);
			DB_INF("netlink server have send");
		}
		else {
			sock_sendto(sp_snd_sock, snd_pkt->out.buf, snd_pkt->out.len, &snd_pkt->paddr);
			DB_INF("server have send");
		}
		mem_free(snd_pkt->in.buf);
		mem_free(snd_pkt->out.buf);
		mem_free(item->arg);
		mem_free(item);
		
    }
}

/*收包线程回调函数*/
static void *msg_rcv_thread_cb(void *arg)
{
	fd_set fds;
	int max_fd = 0, ipc_fd;
	struct timeval tv;
    while (1)
    {
        /*1. 通过select()函数在sp_rcv_sock上进行监听收包,超时时间为2秒
         *  1.1. 如果超时且没有数据包可以收取,则sleep(1),随后继续从第1步开始轮训;
         *  1.2. 如果有数据包待收取,则继续执行后续的步骤*/
        /*2. 分配相应的收包buffer*/
        /*3. 调用sock_recvfrom()函数从sp_rcv_sock上收取数据包,并将对端地址信息一并获取回来,以便发送响应报文时使用*/
        /*4. 分配一个msg_pkt_t结构的对象pkt,并将收取的数据包buffer添加到pkt->in中,且将对端地址信息存入到pkt->paddr中*/
        /*5. 获取收包队列的锁*/
        /*6. 将pkt入队到收包队列中*/
        /*7. 释放收包队列的锁*/
        /*8. 调用thread_pool_worker_add()函数往业务线程池中增加一个worker*/
        //thread_pool_worker_add(sp_handle_pool, msg_handle_cb, NULL);
        /*9. 如果收包线程正在销毁,则推出while(1)循环*/
		tv.tv_sec = 60;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(sp_rcv_sock->fd, &fds);
		if (sp_rcv_sock->fd > max_fd)
			max_fd = sp_rcv_sock->fd;
		
		FD_SET(sp_nlk_rcv_sock->fd, &fds);
		if (sp_nlk_rcv_sock->fd > max_fd)
			max_fd = sp_nlk_rcv_sock->fd;
		
		if (select(max_fd + 1, &fds, NULL, NULL, &tv) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
		}
		if (FD_ISSET(sp_rcv_sock->fd, &fds)) {
			msg_pkt_t* msg = (msg_pkt_t*)mem_alloc(mempool_pkt);
			msg->in.buf = mem_alloc(mempool_buf);
			msg->in.offset = 0;
			msg->in.size = mempool_buf->unitsize;
			if (sock_recvfrom(sp_rcv_sock, msg->in.buf, msg->in.size, &msg->paddr) < 0) {
				mem_free(msg->in.buf);
				mem_free(msg);
				continue;
			}
			DB_INF("server have recv");
			msg->out.buf = mem_alloc(mempool_buf);
			queue_item_t *item = (queue_item_t *)mem_alloc(mempool_queue_item);
			item->arg = msg;
			pthread_mutex_lock(&sp_rcv_queue->mutex);
			queue_enqueue(sp_rcv_queue, item);
			pthread_mutex_unlock(&sp_rcv_queue->mutex);
			thread_pool_worker_add(sp_handle_pool, msg_handle_cb, NULL);
		}
		if (FD_ISSET(sp_nlk_rcv_sock->fd, &fds)) {
			
			msg_pkt_t* msg = (msg_pkt_t*)mem_alloc(mempool_pkt);
			msg->in.buf = mem_alloc(mempool_buf);
			msg->in.offset = sizeof(struct nlmsghdr);
			msg->in.size = mempool_buf->unitsize;
			if (sock_recvfrom(sp_nlk_rcv_sock, msg->in.buf, msg->in.size, &msg->paddr) < 0) {
				mem_free(msg->in.buf);
				mem_free(msg);
				continue;
			}
			DB_INF("netlink server have recv");
			msg->out.buf = mem_alloc(mempool_buf);		
			queue_item_t *item = (queue_item_t *)mem_alloc(mempool_queue_item);
			item->arg = msg;
			pthread_mutex_lock(&sp_rcv_queue->mutex);
			queue_enqueue(sp_rcv_queue, item);
			pthread_mutex_unlock(&sp_rcv_queue->mutex);
			thread_pool_worker_add(sp_handle_pool, msg_handle_cb, NULL);
		}

		
    }
}

/*根据命令获取msg_module_cmd_t*/
static msg_module_cmd_t *msg_get_cmdfunc(const int32 cmd)
{
	msg_module_cmd_t *msg_cmd = NULL;
	list_for_each_entry(msg_cmd, &s_self_cmds, list) {
		if ( msg_cmd->cmd == cmd )
			return msg_cmd;
	}
	return NULL;
}

/*本模块的命令注册*/
int32 msg_cmd_register(const int32 cmd,
                       msg_cmd_handle_cb cb)
{
	if (msg_get_cmdfunc(cmd))
		return -1;
	msg_module_cmd_t *msg_cmd = (msg_module_cmd_t *)malloc(sizeof(msg_module_cmd_t));
	msg_cmd->cmd = cmd;
	msg_cmd->func = cb;
	list_add(&(msg_cmd->list), &s_self_cmds);
	return 0;
}

/*命令注销*/
int32 msg_cmd_unregister(const int32 cmd)
{
	msg_module_cmd_t* p = NULL;
	msg_module_cmd_t* next = NULL;
	list_for_each_entry_safe(p, next, &s_self_cmds, list) {
		if ( p->cmd == cmd ) {
			list_del(&p->list);
			free(p);
			break;
		}
	}
	return 0;
}

/*注销所有命令*/
int32 msg_cmd_unregister_all(void)
{
	msg_module_cmd_t* p = NULL;
	msg_module_cmd_t* next = NULL;
	list_for_each_entry_safe(p, next, &s_self_cmds, list) {	
		list_del(&p->list);
		free(p);
		DB_INF("unregister MY");
	}
	return 0;
}

/*消息通信对端模块信息注册*/
int32 msg_dst_module_register_unix(const int32 mid           /*对端模块ID*/
								) 
{
	msg_module_t *msg_module = (msg_module_t *)malloc(sizeof(msg_module_t));
	msg_module->mid = mid;
	msg_module->addr.un_addr.sun_family = AF_UNIX;
	memset(msg_module->addr.un_addr.sun_path, 0, sizeof(msg_module->addr.un_addr.sun_path));
	snprintf(msg_module->addr.un_addr.sun_path, sizeof(msg_module->addr.un_addr.sun_path)-1, "/tmp/%d_rcv", mid);
	INIT_LIST_HEAD(&msg_module->cmd_list);
	list_add(&(msg_module->list), &s_dst_modules);
	return 0;
}

/*消息通信对端模块信息注册*/
int32 msg_dst_module_register_netlink(const int32 mid) 		 /*对端模块ID*/
								
{
	msg_module_t *msg_module = (msg_module_t *)malloc(sizeof(msg_module_t));
	msg_module->mid = mid;
	
	msg_module->addr.nl_addr.nl_family = AF_NETLINK;
	msg_module->addr.nl_addr.nl_pid = 0;
	msg_module->addr.nl_addr.nl_groups = 0;
	INIT_LIST_HEAD(&msg_module->cmd_list);
	list_add(&(msg_module->list), &s_dst_modules);
	return 0;
}


/*注销对端模块
	如果为-1注销所有模块
*/

int32 msg_dst_module_unregister(const int32 mid)
{
	msg_module_t* p_module = NULL;
	msg_module_t* next_module = NULL;

	if (mid == -1) {
		list_for_each_entry_safe(p_module, next_module, &s_dst_modules, list) {	
			list_del(&p_module->list);			
			free(p_module);
		}
	} else {
		list_for_each_entry_safe(p_module, next_module, &s_dst_modules, list) {
			if ( p_module->mid == mid ) {
				list_del(&p_module->list);				
				free(p_module);
				break;
			}
		}
	}
	return 0;
}

int32 free_rcv_buf(void *rcv_buf)
{
	msg_t *msg = container_of(rcv_buf, msg_t, data);
	if (MODULE_TYPE_GET(msg->cmd) == USER_MODULE)
		mem_free((void *)msg);
	else
		mem_free((void *)msg - sizeof(struct nlmsghdr));
	return 0;
}


