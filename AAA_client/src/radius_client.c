#include	"config.h"
#include	"includes.h"
#include	"freeradius-client.h"
#include	"pathnames.h"
#include	"message.h"
#include    "list.h"
#include     "log.h"
#define RC_CONFIG_FILE "/usr/local/etc/radiusclient/radiusclient.conf"
static char *pname = NULL;
char		*default_realm = NULL;
rc_handle	*rh = NULL;
pthread_mutex_t auth_mutex;
static int pipefd[2];

typedef struct authenticated_cfg_st{
	uint32 ipaddr;
	uint8 mac[6];
    int8 acct_status;   /*0:none; 1:accounting*/
    int8 acct_policy;   /*1:accounting by time; 2:accounting by flow; 3(1&2):accounting by time and flow*/
    uint64 total_seconds;
    uint64 total_flows;
}authenticated_cfg_t;

typedef struct user_info
{
	char name[20];		//字符串
	char pwd[20];		//字符串
	unsigned char mac[6];
	uint32 ipaddr;
}user_info_t;

char temp_mac[6] = {0};
int tem = 0;

typedef struct auth_ok_user
{
	struct list_head list;
	unsigned char mac[6];
	time_t t;
}auth_ok_user_t;

static LIST_HEAD(auth_ok_list);    /*认证通过链表*/

int32 auth_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	char 		msg[PW_MAX_MSG_SIZE], username_realm[256];
	VALUE_PAIR 	*send = NULL, *received = NULL, *vendor = NULL;
	uint32_t		service;
	int result, ret = -1;
	
//	if (ilen != sizeof(user_info_t))
//		goto error;
	
	user_info_t *u = (user_info_t *)ibuf;
/*
	strncpy(username_realm, u->name, sizeof(username_realm));

	if ((strchr(username_realm, '@') == NULL) && default_realm &&
	    (*default_realm != '\0'))
	{
		strncat(username_realm, "@", sizeof(username_realm)-strlen(username_realm)-1);
		strncat(username_realm, default_realm, sizeof(username_realm)-strlen(username_realm)-1);
	}

	if (rc_avpair_add(rh, &send, PW_USER_NAME, username_realm, -1, 0) == NULL)
		goto error;

	if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, u->pwd, -1, 0) == NULL)
		goto error;

	service = PW_FRAMED;
	if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL)
		goto error;

	result = rc_auth(rh, 0, send, &received, msg);
	if (result == OK_RC) {
		fprintf(stderr, "\"%s\" RADIUS Authentication OK \n", u->name);
		auth_ok_user_t *auth_ok_u = malloc(sizeof(auth_ok_user_t));
		memcpy(auth_ok_u->mac, u->mac, sizeof(auth_ok_u->mac));
		auth_ok_u->t = time(NULL);
		pthread_mutex_lock(&auth_mutex);
		list_add(&auth_ok_u->list, &auth_ok_list);
		pthread_mutex_unlock(&auth_mutex);
		AAA_LOG("%02x %02x %02x %02x %02x %02x, time:%d\n", auth_ok_u->mac[0], auth_ok_u->mac[1],
			auth_ok_u->mac[2], auth_ok_u->mac[3], auth_ok_u->mac[4], auth_ok_u->mac[5],auth_ok_u->t);
		ret = 0;
	}
	else {
		fprintf(stderr, "\"%s\" RADIUS Authentication failure (RC=%i)  \n", u->pwd, result);
		ret = ERR_CODE_AUTHFAIL;
	}
	*olen = 0;
	
	
error:
	if (received)
		rc_avpair_free(received);
	if (send)
		rc_avpair_free(send);
	return ret;		
	*/


	auth_ok_user_t *auth_ok_u = malloc(sizeof(auth_ok_user_t));
	memcpy(auth_ok_u->mac, u->mac, sizeof(auth_ok_u->mac));
	auth_ok_u->t = time(NULL);
	pthread_mutex_lock(&auth_mutex);
	list_add(&auth_ok_u->list, &auth_ok_list);
	pthread_mutex_unlock(&auth_mutex);
	
	authenticated_cfg_t to_as;
	memset(&to_as, 0, sizeof(authenticated_cfg_t));
	memcpy(to_as.mac, u->mac, 6);
	to_as.total_seconds = 60;
	to_as.acct_status = 1;
	to_as.acct_policy = 3;
	to_as.total_flows = -1;
	to_as.ipaddr = u->ipaddr;
	char *rcv_buf;
	int rlen = 0;
	printf("send to as\n");
	if (msg_send_syn( MSG_CMD_AS_AUTHENTICATED_ADD,&to_as, sizeof(to_as), &rcv_buf, &rlen) != 0)
		printf("MSG_CMD_AS_AUTHENTICATED_ADD err\n ");
	if (rcv_buf)
		free_rcv_buf(rcv_buf);
	*olen = 0;
	return 0;
	
}

int32 user_timeout(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	if (ilen != 6)
		return -1;
	auth_ok_user_t *p;
	auth_ok_user_t *n;
	printf("have recv timeout %d\n", ilen);
	pthread_mutex_lock(&auth_mutex);
	list_for_each_entry_safe(p, n, &auth_ok_list, list) {
		if (memcmp(p->mac, ibuf, sizeof(p->mac)) == 0) {
			list_del(&p->list);
			free(p);
			break;
		}
	}
	pthread_mutex_unlock(&auth_mutex);
	*olen = 0;
	return 0;
}

void sig_hander( int sig )  
{  
	//	msg_final(); 
//	rc_dict_free(rh);
//	rc_config_free(rh);
//	exit(0);
	int save_errno = errno;
	int msg = sig;
	send(pipefd[1], (char *)&msg, 1, 0);
	errno = save_errno;
} 

int delete_mac() 
{
	char *rcv_buf = NULL;
	int rlen = 0;
	auth_ok_user_t *u = NULL;
	u = list_first_entry(&auth_ok_list, auth_ok_user_t, list);
	
	if (&u->list != &auth_ok_list) {
		printf("send delete to as\n");
		if (msg_send_syn( MSG_CMD_AS_AUTHENTICATED_DELETE, u->mac, sizeof(u->mac), &rcv_buf, &rlen) != 0) {
			printf("MSG_CMD_AS_AUTHENTICATED_DELETE err\n ");
			
		} else {
			pthread_mutex_lock(&auth_mutex);
			list_del(&u->list);
			pthread_mutex_unlock(&auth_mutex);
		}
	} 
//		else {
//		char temp_mac[6] = {0};
//		str2mac("78:a3:51:32:39:87", temp_mac);
//		if (msg_send_syn( MSG_CMD_AS_AUTHENTICATED_DELETE, temp_mac, sizeof(temp_mac), &rcv_buf, &rlen) != 0)
//			printf("MSG_CMD_AS_AUTHENTICATED_DELETE err\n ");
//	}
	printf("free before\n");
	if (rcv_buf)
		free_rcv_buf(rcv_buf);
	printf("free after\n");

}




main (int argc, char **argv)
{

	int i = 0, ret = -1;
	pname = (pname = strrchr(argv[0],'/'))?pname+1:argv[0];

	rc_openlog(pname);
	if ((rh = rc_read_config(RC_CONFIG_FILE)) == NULL)
		return ERROR_RC;

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0)
		return ERROR_RC;
	default_realm = rc_conf_str(rh, "default_realm");
	pthread_mutex_init(&auth_mutex, NULL);
	ret = socketpair(PF_UNIX, SOCK_STREAM, 0, pipefd);
	msg_init(MODULE_RADIUS);
	msg_cmd_register(MSG_CMD_RADIUS_USER_AUTH, auth_handler);
	msg_cmd_register(MSG_CMD_RADIUS_AUTH_TIMEOUT, user_timeout);
	msg_dst_module_register_netlink(MODULE_AS);
	signal(SIGINT, sig_hander);
	signal(SIGTERM, sig_hander);
	struct timeval tv;
	fd_set fds;
	int max_fd = 0;
	while (1) {
		//sleep(30);
		//delete_mac();
		tv.tv_sec = 60;
		tv.tv_usec = 0;
		FD_ZERO(&fds);
		FD_SET(pipefd[0], &fds);
		if (pipefd[0] > max_fd)
			max_fd = pipefd[0];
		
		if (select(max_fd + 1, &fds, NULL, NULL, &tv) < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
		}
		if (FD_ISSET(pipefd[0], &fds)) {
			char signals[100];
			ret = recv(pipefd[0], signals, sizeof(signals), 0);
			if (ret > 0) {
				for(i = 0; i < ret; i++) {
					switch(signals[i]) {
					case SIGTERM:
					case SIGINT:
						msg_final(); 
						exit(0);
						break;
					}
				}
			}
		}
	}

	return 0;

}
