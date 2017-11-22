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
}user_info_t;

typedef struct user_tel_info
{
	char tel[20];		//字符串
	char pwd[20];
	unsigned char mac[6];
}user_tel_info_t;

char *cgi_mac2str(uint8_t *mac)
{
	char *str = malloc(20);
	memset(str, 0, 20);
	snprintf(str, 20, "%02X:%02X:%02X:%02X:%02X:%02X",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return str;
}

int cgi_str2mac(char *str, unsigned char *mac)
{
	int i = 0, j = 0;
	unsigned char v = 0;

	for (i = 0; i < 17; i++) {
		if (str[i] >= '0' && str[i] <= '9') {
			v = str[i] - '0';
		} else if (str[i] >= 'a' && str[i] <= 'f') {
			v = str[i] - 'a' + 10;
		} else if (str[i] >= 'A' && str[i] <= 'F') {
			v = str[i] - 'A' + 10;
		} else if (str[i] == ':' || str[i] == '-' ||
					str[i] == ',' || str[i] == '\r' ||
					str[i] == '\n') {
			continue;
		} else if (str[i] == '\0') {
			return 0;
		} else {
			return -1;
		}
		if (j%2)
			mac[j/2] += v;
		else
			mac[j/2] = v*16;
		j++;
		if (j/2 > 5)
			break;
	}
	return 0;
}


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
	
	snd_msg->cmd = RADIUS_AUTH;
	snd_msg->dmid = MODULE_GET(RADIUS_AUTH);
	snd_msg->dlen = sizeof(user_info_t);
	if ((temp_fd = mkstemp(file_temp)) < 0) {
		CGI_LOG("mktemp error");
		goto out;
	}
	temp_sock = unix_sock_init(file_temp);
	
	sock_addr_u dst_addr;
	dst_addr.un_addr.sun_family = AF_UNIX;
	memset(dst_addr.un_addr.sun_path, 0, sizeof(dst_addr.un_addr.sun_path));
	strncpy(dst_addr.un_addr.sun_path, "/tmp/radius_rcv", sizeof(dst_addr.un_addr.sun_path)-1);
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
	
	snd_msg->cmd = GATEWAY_QUERY;
	snd_msg->dmid = MODULE_GET(GATEWAY_QUERY);
	snd_msg->dlen = sizeof(user_info_t);
	if ((temp_fd = mkstemp(file_temp)) < 0) {
		CGI_LOG("mktemp error");
		goto out;
	}
	temp_sock = unix_sock_init(file_temp);
	
	sock_addr_u dst_addr;
	dst_addr.un_addr.sun_family = AF_UNIX;
	memset(dst_addr.un_addr.sun_path, 0, sizeof(dst_addr.un_addr.sun_path));
	strncpy(dst_addr.un_addr.sun_path, "/tmp/gateway_rcv", sizeof(dst_addr.un_addr.sun_path)-1);
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
		con->html_path = "error.html";
		html_tag_add(&con->tag_list, "zc:error", "error_input");
		goto out;
	}
		
	strncpy(user.name, name, sizeof(user.name) - 1);
	strncpy(user.pwd, pwd, sizeof(user.pwd) - 1);
	cgi_str2mac(mac, user.mac);
	if (auth_handle(&user) == 0) {
		con->html_path = "auth_success.html";
	} else {
		con->html_path = "auth_fail.html";
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
		con->html_path = "error.html";
		html_tag_add(&con->tag_list, "zc:error", "error_input");
		goto out;
	}
	
	if (query_handle(mac, &user) == 0) {
  		con->html_path = "query_ok.html";
		char *r_mac = cgi_mac2str(user.mac);
		html_tag_add(&con->tag_list, "zc:tel", user.tel);
		html_tag_add(&con->tag_list, "zc:pwd", user.pwd);
		html_tag_add(&con->tag_list, "zc:mac", r_mac);
		CGI_LOG("tel: %s, pwd: %s, mac: %s\n", user.tel, user.pwd, r_mac);
		free(r_mac);
	} else {
		con->html_path = "index.html";
		html_tag_add(&con->tag_list, "zc:mac", mac);
	}
	
out:
	
	return 0;
}

