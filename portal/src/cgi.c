#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include "cJSON.h"
#include "message.h"
#include "sock.h"
#include "log.h"
#include "tools.h"
#include "protocol.h"
#include "connection.h"
#include <sys/stat.h>

enum {

CGI_ERR_NAMEPASSWD = 10001,
CGI_ERR_OTHER = 10002
};

typedef struct user_info
{
	char name[20];		//字符串
	char pwd[20];		//字符串
	unsigned char mac[6];
	uint32 ipaddr;
}user_info_t;

typedef struct user_tel_info
{
	char tel[20];		//字符串
	char pwd[20];
	unsigned char mac[6];
}user_tel_info_t;

enum {
	CGI_ERR_FAIL = 10001,
	CGI_ERR_INPUT,
	CGI_ERR_MALLOC,
	CGI_ERR_EXIST,
	CGI_ERR_NONEXIST,
	CGI_ERR_FULL,
	CGI_ERR_NOLOGIN,
	CGI_ERR_NOSUPPORT,
	CGI_ERR_ACCOUNT_NOTREADY,
	CGI_ERR_TIMEOUT,
	CGI_ERR_FILE,
	CGI_ERR_RULE,
};

int auth_handle(user_info_t *user)
{
	int temp_fd = 0, len = 0, ret = -1;
	char file_temp[20] = {0};
	msg_t *snd_msg = NULL;
	msg_t *rcv_msg = NULL;
	socket_t *temp_sock = NULL;
	int8 *rcv_buf = NULL;
	strcpy(file_temp, "/tmp/test.XXXXXX");
	snd_msg = malloc(sizeof(msg_t));
	
	snd_msg->cmd = MSG_CMD_RADIUS_USER_AUTH;
	snd_msg->dmid = MODULE_GET(MSG_CMD_RADIUS_USER_AUTH);
	snd_msg->dlen = sizeof(user_info_t);
	if ((temp_fd = mkstemp(file_temp)) < 0) {
		CGI_LOG("mktemp error");
		goto out;
	}
	temp_sock = unix_sock_init(file_temp);
	
	sock_addr_u dst_addr;
	dst_addr.un_addr.sun_family = AF_UNIX;
	memset(dst_addr.un_addr.sun_path, 0, sizeof(dst_addr.un_addr.sun_path));
	snprintf(dst_addr.un_addr.sun_path, sizeof(dst_addr.un_addr.sun_path)-1, "/tmp/%d_rcv", MODULE_GET(snd_msg->cmd));
	if (!temp_sock)
		goto out;
	len = sock_sendmsg_unix(temp_sock, snd_msg, sizeof(msg_t), user, sizeof(user_info_t), &dst_addr);
	
	if (len <= 0)
	goto out;
	rcv_buf = malloc(2048);
	len = sock_recvfrom(temp_sock, rcv_buf, 2048, NULL);
	if (len <= 0)
		goto out;
	rcv_msg = rcv_buf;
	ret = rcv_msg->result;

out:
	if (temp_fd > 0)
		close(temp_fd);
	if (snd_msg)
		free(snd_msg);
	if (temp_sock) 
		sock_delete(temp_sock);
	if (rcv_buf) {
		free(rcv_buf);
	}
	return ret;
}

int query_handle(char *mac, user_tel_info_t *user)
{
	int temp_fd = 0, len = 0, ret = -1;
	char file_temp[20] = {0};
	msg_t *snd_msg = NULL;
	msg_t *rcv_msg = NULL;
	socket_t *temp_sock = NULL;
	int8 *rcv_buf = NULL;
	strcpy(file_temp, "/tmp/test.XXXXXX");
	snd_msg = malloc(sizeof(msg_t));
	
	snd_msg->cmd = MSG_CMD_MANAGE_USER_QUERY;
	snd_msg->dmid = MODULE_GET(MSG_CMD_MANAGE_USER_QUERY);
	snd_msg->dlen = sizeof(user_info_t);
	if ((temp_fd = mkstemp(file_temp)) < 0) {
		CGI_LOG("mktemp error");
		goto out;
	}
	temp_sock = unix_sock_init(file_temp);
	
	sock_addr_u dst_addr;
	dst_addr.un_addr.sun_family = AF_UNIX;
	memset(dst_addr.un_addr.sun_path, 0, sizeof(dst_addr.un_addr.sun_path));
	snprintf(dst_addr.un_addr.sun_path, sizeof(dst_addr.un_addr.sun_path)-1, "/tmp/%d_rcv", MODULE_GET(snd_msg->cmd));
	if (!temp_sock)
		goto out;
	len = sock_sendmsg_unix(temp_sock, snd_msg, sizeof(msg_t), mac, strlen(mac) + 1, &dst_addr);
	
	if (len <= 0)
	goto out;
	rcv_buf = malloc(2048);
	len = sock_recvfrom(temp_sock, rcv_buf, 2048, NULL);
	if (len <= 0)
		goto out;
	rcv_msg = rcv_buf;
	ret = rcv_msg->result;
	if (ret == 0)
		memcpy(user, rcv_msg->data, sizeof(user_tel_info_t));

out:
	if (temp_fd > 0)
		close(temp_fd);
	if (snd_msg)
		free(snd_msg);
	if (temp_sock) 
		sock_delete(temp_sock);
	if (rcv_buf) {
		free(rcv_buf);
	}
	return ret;
}

int cgi_sys_auth_handler(connection_t *con)
{
	char *name = con_value_get(con,"name");
	char *pwd = con_value_get(con, "pwd");
	char *mac = con_value_get(con,"mac");
	CGI_LOG("name: %s, pwd: %s, msc: %s\n", name, pwd, mac);
	user_info_t user= {{0}, {0}, {0}};
	if (!name || !pwd || !mac) {
		con->html_path = "portal/error.html";
		html_tag_add(&con->tag_list, "zc:error", "error_input");
		goto out;
	}
		
	strncpy(user.name, name, sizeof(user.name) - 1);
	strncpy(user.pwd, pwd, sizeof(user.pwd) - 1);
	str2mac(mac, user.mac);
	if (auth_handle(&user) == 0) {
		con->html_path = "portal/auth_success.html";
	} else {
		con->html_path = "portal/auth_fail.html";
	}
	
out:
	return 0;
	
}

int cgi_sys_login_handler(connection_t *con)
{
	char *mac = con_value_get(con,"mac");
	char *ip = con_value_get(con,"ip");
	CGI_LOG("mac: %s\n", mac);
	user_info_t user= {{0}, {0}, {0}, 0};
	struct in_addr user_ip;
	user_ip.s_addr = inet_addr(ip);
	
	strncpy(user.name, "18202822785", sizeof(user.name) - 1);
	strncpy(user.pwd, "1231245", sizeof(user.pwd) - 1);
	str2mac(mac, user.mac);
	user.ipaddr = user_ip.s_addr;
	
	if (auth_handle(&user) == 0) {
		con->html_path = "portal/auth_success.html";
	} else {
		con->html_path = "portal/auth_fail.html";
	}
	
out:
	return 0;	
}

int cgi_sys_query_handler(connection_t *con)
{	
	char* mac = con_value_get(con,"mac");
	
//	cgi_str2mac()
	user_tel_info_t user;
	memset(&user, 0, sizeof(user_tel_info_t));
	if (!mac) {
		con->html_path = "portal/error.html";
		html_tag_add(&con->tag_list, "zc:error", "error_input");
		goto out;
	}
	
	if (query_handle(mac, &user) == 0) {
  		con->html_path = "portal/query_ok.html";
		char *r_mac = mac2str(user.mac);
		html_tag_add(&con->tag_list, "zc:tel", user.tel);
		html_tag_add(&con->tag_list, "zc:pwd", user.pwd);
		html_tag_add(&con->tag_list, "zc:mac", r_mac);
		CGI_LOG("tel: %s, pwd: %s, mac: %s\n", user.tel, user.pwd, r_mac);
		free(r_mac);
	} else {
		con->html_path = "portal/index.html";
		html_tag_add(&con->tag_list, "zc:mac", mac);
	}
	
out:
	
	return 0;
}

