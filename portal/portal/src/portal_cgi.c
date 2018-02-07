#include <stdio.h>
#include <stdlib.h>
#include "cJSON.h"
#include "message.h"
#include "sock.h"
#include "log.h"
#include "protocol.h"
#include "connection.h"

/*
typedef struct user_info
{
	char name[20];		//字符串
	char pwd[20];		//字符串
	unsigned char mac[6];
}user_info_t;

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
*/

int main()
{
/*
	char *str_len = NULL;
	int len = 0;
	char buf[100] = {0};
	user_info_t user;
	cJSON *root;
	char *out = NULL;	
	int ret = -1;
	
	str_len = getenv("CONTENT_LENGTH");
	if ((str_len == NULL) || (sscanf(str_len, "%d", &len)!=1) || (len>80)) {
	
		root = cJSON_CreateObject();
		cJSON_AddNumberToObject(root,"login",0);
		cJSON_AddNumberToObject(root,"error",CGI_ERR_OTHER);
		goto reply_print;
	}
	fgets(buf, len+1, stdin);
	memset(&user, 0, sizeof(user_info_t));
	sscanf(buf, "name=%[^&]&password=%s",user.name,user.pwd);
	memset(user.mac, 0xFF, 6);
	root = cJSON_CreateObject();
	ret = auth_handle(&user);
	cJSON_AddNumberToObject(root,"login",0);
	cJSON_AddNumberToObject(root,"error",ret);

reply_print:
	printf("%s\r\n\r\n","Content-Type:application/json;charset=UTF-8"); 

	out=cJSON_Print(root);
	cJSON_Delete(root);
	printf("%s\n", out);
	if (out)
		free(out);
*/
	connection_t con;
	connection_init(&con);
	connection_handel(&con);
	con.free(&con);
	return 0;
}