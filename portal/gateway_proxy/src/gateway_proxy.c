#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include    "cJSON.h"
#include	"message.h"
#include    "http_call.h"
#include    "nlk_ipc.h"
#include    "log.h"
#include    "def.h"
#include    "list.h"
#include <errno.h>
#include <fcntl.h>
#include "timer.h"
#include "libcom.h"
#include <sys/wait.h>


#define MAX_JSON_LEN 2048

#define GMC_URL_HEART "http://192.168.1.81:8888/gateway/heartbeat"   
//"http://192.168.20.1:81/cgi-bin/temp_cgi?opt=check_login"
#define GMC_URL_RESULT "http://192.168.1.81:8888/gateway/taskResult"
#define TOKEN_URL "http://192.168.1.160:2080/authentication/platform/token/2/"
#define USER_QUERY_URL "http://192.168.1.160:2080/authentication/gateway/user/2/"
#define USER_REGISTER_URL "http://192.168.1.160:2080/authentication/gateway/user/register/2/"
#define TEXT_CODE_URL "http://192.168.1.5:2080/authentication/getAuthcode"


#define PORTAL_FILE "/tmp/portal.tar.gz"
#define SYSBIN_FILE "/tmp/openwrt-ramips-mt7621-mt7621-squashfs-sysupgrade.bin"

#define PORTAL_WEB_DIR "/www/"

enum task_id {
	TASK_SYSTEM_REBOOT   = 100,
	TASK_SYSTEM_UPGRADE  = 101,           
	TASK_NET_VLANSET     = 200,             
	TASK_PORTAL_HTML_UPDATE   = 300,        
	TASK_PORTAL_RADIUS_UPDATE = 301
};


static int pipefd[2];
static LIST_HEAD(query_user_list);
pthread_mutex_t query_mutex;
pthread_mutex_t text_mutex;
pthread_mutex_t authing_mutex;

typedef struct portal_cfg_st{
    int32 apply;/*0:interface; 1:vlan*/
    union {
        int8 ifname[IFNAME_SIZE];
        uint16 vlan_id;
    };
    int8 url[URL_SIZE];
}portal_cfg_t;

//char * http_post(const char *url,const char * post_str);  
//extern cJSON *cJSON_Parse(const char *value);

enum {
	TASK_UPDATE_POTAL_HTML,
	TASK_UPDATE_AAA_ADDRESS,
	TASK_UPDATE_ADVERTISE_JS,
	TASK_UPDATE_SYSTEM_FIRMWARE
};

typedef struct gateway_info {
	char mac[20];
	char hard_version[8];
	char soft_version[8];
	char vendor[20];
	char cpu_load[32];
	char wan_mode[8];
	int memory_total;
	int memory_free;
	int disk_total;
	int disk_available;
	char wan_ip[20];
	char lan_ip[20];
	int date;
	int uptime;
	
}gateway_info_t;

typedef struct advertising_cfg_st{
    uint32 id;
    int32 type;
    int8 url[URL_SIZE];
}advertising_cfg_t;

typedef enum ads_policy_en{
    ADS_POLICY_NONE           = 0x00, /*none*/
    ADS_POLICY_TIME_INTERVAL  = 0x01, /*time interval*/
    ADS_POLICY_FLOW_INTERVAL  = 0x02, /*flow interval*/
    ADS_POLICY_EVERYTIME      = 0x04  /*everytime. valid when ads->type is ADS_TYPE_EMBED*/
}ads_policy_e;
/*advertising option*/
typedef enum ads_option_en{
    ADS_OPTION_RANDOM   = 0x00, /*random*/
    ADS_OPTION_LOOPING  = 0x01  /*looping*/
}ads_option_e;

typedef struct advertising_policy_st{
    int32 policy;
    int32 option;
    int32 type;
    uint64 time_interval;
    uint64 flow_interval;
}advertising_policy_t;

static gateway_info_t gateway;
static LIST_HEAD(tel_text_users);    /*通信对端模块信息*/
static LIST_HEAD(authing_users); 


typedef struct token_info_st{
	char token_val[64];
	int token_time;
	int if_lgoin;
}token_info_t;

static token_info_t gw_token;

int http_send(char *url, cJSON *send, cJSON **recv)
{
	int ret = -1, rlen = 0;
	char *jstr = NULL, *back_str = NULL;
	cJSON *obj = NULL;
	char cmd[4096] = {0};
	back_str = (char*)malloc(4096);
	if (!send) {
		snprintf(cmd, sizeof(cmd) - 1, "curl --connect-timeout 2 -m 2 -s -H \"DevMac: %s\" %s", 
		gateway.mac, url);
	} else {
		jstr = cJSON_PrintUnformatted(send); 
		printf("http send %s\n", jstr);
		snprintf(cmd, sizeof(cmd) - 1, 
		"curl --connect-timeout 2 -m 2 -s -H \"Content-Type:application/json\" -H \"DevMac: %s\" -X POST --data '%s' %s", 
		gateway.mac, jstr, url);
	}
	rlen = shell_printf(cmd, back_str, 4096);
	if (rlen <= 0) {
		GATEWAY_LOG("http return null\n");
		printf("http return null\n");
		goto out;
	}
	printf("http recv %s\n", back_str);
	obj = cJSON_Parse(back_str);
	if (!obj)
		goto out;
	cJSON *result = cJSON_GetObjectItem(obj, "result");
	if (!result)
		goto out;
	ret = result->valueint;
	if (ret)
		goto out;
	*recv = obj;
out:
	if (back_str)
		free(back_str);
	if (ret)
		recv = NULL;
	return ret;
}

int get_token()
{
	char *back_str = NULL;
	char cmd_token[1024] = {0};
	int ret = -1, rlen = 0;
	cJSON *obj = NULL;
	back_str = (char*)malloc(4096);
	gw_token.token_time = time(NULL);

	snprintf(cmd_token, sizeof(cmd_token) - 1, 
	"curl --connect-timeout 2 -m 2 -s %s%d", TOKEN_URL, gw_token.token_time);
	rlen = shell_printf(cmd_token, back_str, 4096);
	if (!back_str) {
		GATEWAY_LOG("http request return null\n");
		goto out;
	}
	printf("token back: %s\n", back_str);
	obj = cJSON_Parse(back_str);
	if (!obj)
		goto out;
	cJSON *code = cJSON_GetObjectItem(obj, "code");
	if (!code || code->valueint)
		goto out;
	cJSON *data = cJSON_GetObjectItem(obj, "data");
	if (!data || !data->valuestring)
		goto out;
	strncpy(gw_token.token_val, data->valuestring, sizeof(gw_token.token_val) - 1);
	gw_token.if_lgoin = 1;
	ret = 0;
out:
	if (obj)
		cJSON_Delete(obj);
	if (back_str)
		free(back_str);
	return ret;
}

int query_list_clear()
{
	user_query_info_t *p= NULL, *n = NULL;
	pthread_mutex_lock(&query_mutex);
	list_for_each_entry_safe(p, n, &query_user_list, user_list) {
		printf("q del\n");
		list_del(&p->user_list);
		free(p);
	}
	pthread_mutex_unlock(&query_mutex);
	return 0;
}

int32 user_query_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{

	int ret = -1;
	cJSON *root = NULL, *obj = NULL;
	char url[128] = {0};
	root = cJSON_CreateObject();
	
	if (!gw_token.if_lgoin)
		get_token();

	user_query_info_t *user_info = (user_query_info_t *)ibuf;
	user_query_info_t *p;

	pthread_mutex_lock(&query_mutex);
	list_for_each_entry(p, &query_user_list, user_list) {
		if (strcmp(user_info->mac, p->mac) == 0 && user_info->auth_type == p->auth_type) {
			memcpy(obuf, p, sizeof(user_query_info_t));
			*olen = sizeof(user_query_info_t);
			ret = 0;
			pthread_mutex_unlock(&query_mutex);
			goto out;
		}
	}
	pthread_mutex_unlock(&query_mutex);
	cJSON_AddStringToObject(root, "userMac", user_info->mac);
	
	cJSON_AddNumberToObject(root, "userType", user_info->auth_type);

	snprintf(url, sizeof(url) - 1, "%s%d/%s", USER_QUERY_URL, 
		gw_token.token_time, gw_token.token_val);
	ret = http_send(url, root, &obj);
	
	user_query_info_t *qu = (user_query_info_t *)obuf;
	memcpy(qu, user_info, sizeof(user_query_info_t));
	qu->if_exist = ret;
	if (!ret) {
		cJSON *data = cJSON_GetObjectItem(obj, "data");
		if (!data && !data->child)
			goto out;
		
		cJSON *utype = cJSON_GetObjectItem(data, "userType");
		cJSON *umac = cJSON_GetObjectItem(data, "userMac");
		cJSON *uname = cJSON_GetObjectItem(data, "username");
		cJSON *upassword = cJSON_GetObjectItem(data, "password");
		if (!utype || !umac || !uname || !upassword)
			goto out;
		qu->auth_type = utype->valueint;
		strncpy(qu->mac, umac->valuestring, sizeof(qu->mac) - 1);
		strncpy(qu->username, uname->valuestring, sizeof(qu->username) - 1);
		strncpy(qu->password, upassword->valuestring, sizeof(qu->password) - 1);
		user_query_info_t *query_cache = malloc(sizeof(user_query_info_t));
		memcpy(query_cache, qu, sizeof(user_query_info_t));
		pthread_mutex_lock(&query_mutex);
		list_add(&query_cache->user_list, &query_user_list);
		printf("q add\n");
		pthread_mutex_unlock(&query_mutex);
	} else if (ret == 1) {
		strncpy(qu->mac, user_info->mac, sizeof(qu->mac) - 1);
		qu->auth_type = user_info->auth_type;
		user_query_info_t *query_cache = malloc(sizeof(user_query_info_t));
		memcpy(query_cache, qu, sizeof(user_query_info_t));
		pthread_mutex_lock(&query_mutex);
		list_add(&query_cache->user_list, &query_user_list);
		pthread_mutex_unlock(&query_mutex);
	} else {
		goto out;
	}
	*olen = sizeof(user_query_info_t);
	ret = 0;
out:
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	if (ret)
		*olen = 0;
	return ret;
}

int32 user_register_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{

	int ret = -1, matched = 0;
	cJSON *root = NULL, *obj = NULL;
	char url[128] = {0};
	user_query_info_t *user_info = ibuf;
	user_query_info_t *p = NULL, *n = NULL;
	pthread_mutex_lock(&text_mutex);
	list_for_each_entry_safe(p, n, &tel_text_users, user_list) {
		if (strcmp(user_info->username, p->username) == 0 && 
				strcmp(user_info->password, p->password) == 0) {
			matched = 1;
			list_del(&p->user_list);
			free(p);
			break;
		}
	}
	pthread_mutex_unlock(&text_mutex);
	if (!matched)
		goto out;
	root = cJSON_CreateObject();
	
	cJSON_AddStringToObject(root, "userMac", user_info->mac);

	cJSON_AddNumberToObject(root, "userType", user_info->auth_type);
	cJSON_AddStringToObject(root, "devIp", gateway.wan_ip);
	cJSON_AddStringToObject(root, "devMac", gateway.mac);
	cJSON_AddStringToObject(root, "ssid", "jfwx608");
	cJSON_AddStringToObject(root, "username", user_info->username);
	cJSON_AddStringToObject(root, "password", user_info->password);

	snprintf(url, sizeof(url) - 1, "%s%d/%s", USER_REGISTER_URL, 
		gw_token.token_time, gw_token.token_val);

	if ((ret = http_send(url, root, &obj)))
		goto out;

	cJSON *result = cJSON_GetObjectItem(obj, "result");
	if (!result || result->valueint)
		goto out;

	pthread_mutex_lock(&query_mutex);
	list_for_each_entry_safe(p, n, &query_user_list, user_list) {
		if (strcmp(user_info->mac, p->mac) == 0 && user_info->auth_type == p->auth_type) {
			list_del(&p->user_list);
			free(p);
		}
	}
	pthread_mutex_unlock(&query_mutex);
	
	ret = msg_send_syn(MSG_CMD_RADIUS_USER_AUTH, user_info, sizeof(user_query_info_t), NULL,0);

	*olen = 0;
out:
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	if (ret)
		*olen = 0;
	return ret;
}

int32 send_tel_code_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	int ret = -1, rlen = 0, verify_code = 0;
	cJSON *root = NULL, *obj = NULL;
	char *jstr = NULL, *back_str = NULL;
	char url[128] = {0}, code_str[64] = {0};
	char cmd_text[2048] = {0};
	root = cJSON_CreateObject();

	user_query_info_t *user_info = ibuf;
	
	cJSON_AddStringToObject(root, "phone", user_info->username);
	cJSON_AddStringToObject(root, "center_id", "2");
	cJSON_AddNumberToObject(root, "time", gw_token.token_time);
	cJSON_AddStringToObject(root, "sing", gw_token.token_val);
	
	verify_code = time(NULL); 
	verify_code = verify_code%1000000;
	snprintf(code_str, sizeof(code_str) - 1, "您的服务码是：%06d【华数WIFI】", verify_code);
	cJSON_AddStringToObject(root, "msg", code_str);
	
//	if ((ret = http_send(TEXT_CODE_URL, root, &obj)))
//		goto out;
	jstr = cJSON_PrintUnformatted(root);
	back_str = (char*)malloc(4096);
	
	snprintf(cmd_text, sizeof(cmd_text) - 1, 
		"curl --connect-timeout 2 -m 2 -s -H \"Content-Type:application/json\" -H \"DevMac: %s\" -X POST --data '%s' %s", 
		gateway.mac, jstr, TEXT_CODE_URL);

	rlen = shell_printf(cmd_text, back_str, 4096);
	printf("http send %s\n", jstr);
	if (rlen <= 0) {
		GATEWAY_LOG("http return null\n");
		printf("return null\n");
		goto out;
	}
	printf("http recv %s\n", back_str);
	obj = cJSON_Parse(back_str);

	cJSON *code = cJSON_GetObjectItem(obj, "code");
	if (!code || code->valueint)
		goto out;
	ret = 0;
	*olen = 0;
	user_query_info_t *need_verify = malloc(sizeof(user_query_info_t));
	memcpy(need_verify, user_info, sizeof(user_query_info_t));
	snprintf(need_verify->password, sizeof(need_verify->password) - 1, "%6d", verify_code);
	user_query_info_t *p = NULL;
	int matched = 0;

	pthread_mutex_lock(&text_mutex);
	list_for_each_entry(p, &tel_text_users, user_list) {
		if (strcmp(p->username, need_verify->username) == 0) {
			strcpy(p->password, need_verify->password);
			free(need_verify);
			matched = 1;
			break;
		}
	}
	if (!matched)
		list_add(&need_verify->user_list, &tel_text_users);
	pthread_mutex_unlock(&text_mutex);
	
out:
	if (jstr)
		free(jstr);
	if (back_str)
		free(back_str);
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	if (ret)
		*olen = 0;
	return ret;
}


void sig_hander( int sig )  
{  
	int save_errno = errno;
	int msg = sig;
	send(pipefd[1], (char *)&msg, 1, 0);
	errno = save_errno;
} 

int portal_wget(int id, int code, unsigned char *md5, char *url)
{
	int i = 0, pid = -1;
	char cmd[512];
	unsigned char temp_md5[32];
	char push_msg[32] = {0};
	pid = fork();
	if (pid < 0)
		return -1;
	else if (pid > 0) 
		return 0;

	snprintf(cmd, sizeof(cmd) - 1, "wget -O %s -T 60 %s", PORTAL_FILE, url);

	for (i = 0; i < 3; i++) {
		if (!system(cmd))
			break;
		sleep(3);
	}
	if (i > 3)
		goto err;
	if (igd_md5sum(PORTAL_FILE, temp_md5)) {
		GATEWAY_LOG("%s calc md5 fail\n", PORTAL_FILE);
		goto err;
	}

	for (i = 0; i < 16; i++)
		sprintf(&cmd[i*2], "%02X", temp_md5[i]);
	if (strncasecmp(cmd, md5, 32)) {
			GATEWAY_LOG("MD5ERR:\n%s\n%s\n", cmd, md5);
			strncpy(push_msg, sizeof(push_msg) - 1, "md5 check err");
			goto err;
	}
	snprintf(cmd, sizeof(cmd), "tar -zxvf %s -C %s",
			PORTAL_FILE, PORTAL_WEB_DIR);
	system(cmd);
	report_task(id, code, 0, NULL);
	snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s", PORTAL_FILE);
	system(cmd);
	exit(0);
err:
	report_task(id, code, 1, push_msg);
	snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s", PORTAL_FILE);
	system(cmd);
	exit(-1);
	
}

int sysbin_wget(int id, int code, unsigned char *md5, char *url)
{
	int i = 0, pid = -1;
	char cmd[512];
	unsigned char temp_md5[32];
	char push_msg[32] = {0};
	pid = fork();
	if (pid < 0)
		return -1;
	else if (pid > 0) 
		return 0;

	snprintf(cmd, sizeof(cmd) - 1, "wget -O %s -T 60 %s", SYSBIN_FILE, url);

	for (i = 0; i < 3; i++) {
		if (!system(cmd))
			break;
		sleep(3);
	}
	if (i > 3)
		goto err;
	if (igd_md5sum(SYSBIN_FILE, temp_md5)) {
		GATEWAY_LOG("%s calc md5 fail\n", PORTAL_FILE);
		goto err;
	}

	for (i = 0; i < 16; i++)
		sprintf(&cmd[i*2], "%02X", temp_md5[i]);
	if (strncasecmp(cmd, md5, 32)) {
			GATEWAY_LOG("MD5ERR:\n%s\n%s\n", cmd, md5);
			strncpy(push_msg, sizeof(push_msg) - 1, "md5 check err");
			goto err;
	}
	report_task(id, code, 0, NULL);
	snprintf(cmd, sizeof(cmd) - 1, "sysupgrade %s &", SYSBIN_FILE);
	system(cmd);
	snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s", PORTAL_FILE);
	system(cmd);
	exit(0);
err:
	report_task(id, code, 1, push_msg);
	snprintf(cmd, sizeof(cmd) - 1, "rm -rf %s", PORTAL_FILE);
	system(cmd);
	exit(-1);
	
}

int report_task(int id, int code,int result, char *msg) {

	int ret = -1;
	cJSON *root = cJSON_CreateObject();
	cJSON *task_arr = cJSON_CreateArray();
	cJSON *obj = NULL;

	obj = cJSON_CreateObject();
	cJSON_AddNumberToObject(obj, "id", id);
	cJSON_AddNumberToObject(obj, "taskCode", code);
	cJSON_AddNumberToObject(obj, "result", result);
	if (msg)
		cJSON_AddStringToObject(obj, "message", msg);
	else
		cJSON_AddNullToObject(obj, "message");
	cJSON_AddItemToArray(task_arr, obj);

	cJSON_AddItemToObject(root, "taskList",task_arr);
	if ((ret = http_send(GMC_URL_RESULT, root, &obj)))
		goto out;
	
out:
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	return ret;
}

int do_task(cJSON *task_list)
{
	printf("do_task\n");
	cJSON *child_item = task_list->child;
	cJSON *task_id = NULL, *task_code = NULL, *task_para = NULL,
			*md5_code = NULL;
	cJSON *download_url = NULL;
	
	char *bask_str = (char*)malloc(4096);
	char cmd_task[4096] = {0};
	int rlen = 0;
	while (child_item) {
		task_id = cJSON_GetObjectItem(child_item, "id");
		task_code = cJSON_GetObjectItem(child_item, "taskCode");
		if (task_code) {
			switch(task_code->valueint) {
			case TASK_SYSTEM_REBOOT:
//				uuci_set("task_record.need_report.reboot=1");
				
				report_task(task_id->valueint, task_code->valueint, 0, NULL);
				rlen = shell_printf("reboot", bask_str, 4096);
				printf("task reboot\n");
				break;
			case TASK_PORTAL_HTML_UPDATE:
				task_para = cJSON_GetObjectItem(child_item, "taskParam");
				if (!task_para) {
					printf("no param\n");
					break;
				}
				download_url = cJSON_GetObjectItem(task_para, "url");
				md5_code = cJSON_GetObjectItem(task_para, "md5Code");
				if (!download_url || !md5_code) {
					printf("no url, or no md5 code");
					break;
				}			
				portal_wget(task_id->valueint, task_code->valueint, md5_code->valuestring, download_url->valuestring);
				break;
			case TASK_SYSTEM_UPGRADE:
				task_para = cJSON_GetObjectItem(child_item, "taskParam");
				if (!task_para) {
					printf("no param\n");
					break;
				}
				download_url = cJSON_GetObjectItem(task_para, "url");
				md5_code = cJSON_GetObjectItem(task_para, "md5Code");
				if (!download_url || !md5_code) {
					printf("no url, or no md5 code");
					break;
				}			
				sysbin_wget(task_id->valueint, task_code->valueint, md5_code->valuestring, download_url->valuestring);
				break;
			}
		}
		child_item = child_item->next;
	
	}
	if (bask_str)
		free(bask_str);
	
	return 0;

}

int send_heart_beat()
{
	//char report_data[MAX_JSON_LEN] = "report_data=";
	//char encode_report[MAX_JSON_LEN] = {0};
	int ret = -1, rlen = 0, status = 0, w_pid = 0;
	cJSON *root = NULL, *obj = NULL;
	char url[128] = {0};
	if (!gw_token.if_lgoin)
		get_token();
	gateway_info_update();
	query_list_clear();
	w_pid = waitpid(-1, &status, WNOHANG);
	printf("wait pid hhhhhhhhhhhhhhhhhhhhhhhhhhhh = %d\n", w_pid);
	root = cJSON_CreateObject();
	
//	cJSON_AddStringToObject(root, "stage", "heartbeat");
//	cJSON_AddStringToObject(root, "devMac", gateway.mac);
	
	cJSON_AddStringToObject(root, "hardVersion", gateway.hard_version);
	cJSON_AddStringToObject(root, "softVersion", gateway.soft_version);
	cJSON_AddStringToObject(root, "vendor", gateway.vendor);
	cJSON_AddStringToObject(root, "wanMode", gateway.wan_mode);
	cJSON_AddStringToObject(root, "wanIp", gateway.wan_ip);
	cJSON_AddStringToObject(root, "lanIp", gateway.lan_ip);
	cJSON_AddStringToObject(root, "cpu", gateway.cpu_load);
	cJSON_AddNumberToObject(root, "memoryTotal", gateway.memory_total);
	cJSON_AddNumberToObject(root, "memoryFree", gateway.memory_free);
	cJSON_AddNumberToObject(root, "diskTotal", gateway.disk_total);
	cJSON_AddNumberToObject(root, "diskAvailable", gateway.disk_available);
	cJSON_AddNumberToObject(root, "date", gateway.date);
	cJSON_AddNumberToObject(root, "uptime", gateway.uptime);
	
	if ((ret = http_send(GMC_URL_HEART, root, &obj)))
		goto out;

	cJSON *result = cJSON_GetObjectItem(obj, "result");
	if (!result || result->valueint)
		goto out;	
	cJSON *data = cJSON_GetObjectItem(obj, "data");
	if (data && data->child && !strcmp(data->child->string, "taskList"))
		do_task(data->child);
	ret = 0;

out:
	if (root)
		cJSON_Delete(root);
	if (obj)
		cJSON_Delete(obj);
	return ret;

}

int gateway_info_init()
{
	char **array = NULL;
	int num = 0, rlen = 0;
	char temp_disk[10] = {0};
	time_t rawtime;
	struct sysinfo info;
	
	if (!uuci_get("network.wan.macaddr", &array, &num)) {
		arr_strcpy(gateway.mac, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("network.wan.proto", &array, &num)) {
		arr_strcpy(gateway.wan_mode, array[0]);
		uuci_get_free(array, num);
	}
	if ((rlen = shell_printf("ifstatus wan | grep \"address\" | grep -oE '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}'",
					gateway.wan_ip, sizeof(gateway.wan_ip))) > 0) {
		gateway.wan_ip[rlen - 1] = '\0';
	}
	if (!uuci_get("system.@system[0].hard_version", &array, &num)) {
		arr_strcpy(gateway.hard_version, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("system.@system[0].soft_version", &array, &num)) {
		arr_strcpy(gateway.soft_version, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("system.@system[0].vendor", &array, &num)) {
		arr_strcpy(gateway.vendor, array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("network.lan.ipaddr", &array, &num)) {
		arr_strcpy(gateway.lan_ip, array[0]);
		uuci_get_free(array, num);
	}

	shell_printf("df | grep rootfs | awk '{printf $2}'", temp_disk, sizeof(temp_disk));
	gateway.disk_total = atoi(temp_disk);
	memset(temp_disk, 0, sizeof(temp_disk));
	shell_printf("df | grep rootfs | awk '{printf $4}'", temp_disk, sizeof(temp_disk));
	gateway.disk_available = atoi(temp_disk);

	time(&rawtime);
	gateway.date = rawtime;
	
	cpu_info_get(gateway.cpu_load);
	
	if (!sysinfo(&info)) {
		gateway.uptime = info.uptime;
		gateway.memory_free = info.freeram;
		gateway.memory_total = info.totalram;
		
	}
	return 0;
					
}

int gateway_info_update()
{
	char **array = NULL;
	int num = 0, rlen = 0;
	char temp_disk[10] = {0};
	time_t rawtime;
	struct sysinfo info;
	if (!uuci_get("network.wan.proto", &array, &num)) {
		arr_strcpy(gateway.wan_mode, array[0]);
		uuci_get_free(array, num);
	}
	if ((rlen = shell_printf("ifstatus wan | grep \"address\" | grep -oE '[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}.[0-9]{1,3}'",
					gateway.wan_ip, sizeof(gateway.wan_ip))) > 0) {
		gateway.wan_ip[rlen - 1] = '\0';
	}
	if (!uuci_get("network.lan.ipaddr", &array, &num)) {
		arr_strcpy(gateway.lan_ip, array[0]);
		uuci_get_free(array, num);
	}

	shell_printf("df | grep rootfs | awk '{printf $4}'", temp_disk, sizeof(temp_disk));
	gateway.disk_available = atoi(temp_disk);
	
	time(&rawtime);
	gateway.date = rawtime;
	cpu_info_get(gateway.cpu_load);
	
	if (!sysinfo(&info)) {
		gateway.uptime = info.uptime;
		gateway.memory_free = info.freeram;
	}
	return 0;
}

unsigned int black_white_mac[6] = {0};

void black_white_list_add_send()
{
	char **array = NULL;
	int num = 0, i = 0;
	if (!uuci_get("acct_config.total_config.black_white_enable", &array, &num)) {
		int enable = atoi(array[0]);
		uuci_get_free(array, num);
		if (!enable)
			return;
	}
	
	if (!uuci_get("acct_config.black_list.black", &array, &num)) {
		for(i = 0; i < num; i++) {
			str2mac(array[i], black_white_mac);
			if (msg_send_syn( MSG_CMD_AS_BLACKLIST_ADD, black_white_mac, sizeof(black_white_mac), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_BLACKLIST_ADD err\n ");
			}else {
				printf("black add success\n");
			}
		}
		uuci_get_free(array, num);
	}
	if (!uuci_get("acct_config.white_list.white", &array, &num)) {
		for(i = 0; i < num; i++) {
			str2mac(array[i], black_white_mac);
			if (msg_send_syn( MSG_CMD_AS_WHITELIST_ADD, black_white_mac, sizeof(black_white_mac), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_WhiteLIST_ADD err\n ");
			}else {
				printf("white add success\n");
			}
		}
		uuci_get_free(array, num);
	}
		
}

void black_list_del_send()
{
	if (msg_send_syn( MSG_CMD_AS_BLACKLIST_DELETE, black_white_mac, sizeof(black_white_mac), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_BLACKLIST_DELETE err\n ");
		}else {
			printf("black delete success\n");
			}
}

advertising_cfg_t temp_adv;
void add_advertise()
{
	char **array = NULL;
	char *res;
	int num = 0, i = 0;
	int adv_size = 0;
	if (!uuci_get("acct_config.total_config.advertise_enable", &array, &num)) {
		int enable = atoi(array[0]);
		uuci_get_free(array, num);
		if (!enable)
			return;
	}
	if (!uuci_get("acct_config.total_config.advertise_size", &array, &num)) {
		adv_size = atoi(array[0]);
		uuci_get_free(array, num);
		char str[64] = {0};
		for (i = 0; i < adv_size; i++) {
			snprintf(str, sizeof(str) - 1, "acct_config.@advertise[%d].id", i);
			if (!uuci_get(str, &array, &num)) {
				temp_adv.id = atoi(array[0]);
				uuci_get_free(array, num);
			}
			snprintf(str, sizeof(str) - 1, "acct_config.@advertise[%d].type", i);
			if (!uuci_get(str, &array, &num)) {
				temp_adv.type = atoi(array[0]);
				uuci_get_free(array, num);
			}
			snprintf(str, sizeof(str) - 1, "acct_config.@advertise[%d].url", i);
			if (!uuci_get(str, &array, &num)) {
				snprintf(temp_adv.url, sizeof(temp_adv.url) - 1, "http://%s/%s", gateway.lan_ip, array[0]);
				uuci_get_free(array, num);
			}
			if (msg_send_syn( MSG_CMD_AS_ADVERTISING_ADD, &temp_adv, sizeof(advertising_cfg_t), NULL, NULL) != 0) {
				printf("MSG_CMD_AS_ADVERTISING_ADD err\n ");
			}else {
				printf("adv add success\n");
			}
		}
	}
	set_adv_policy();
}

int tempid;
void delete_advertise()
{
	temp_adv.id = tempid;
	temp_adv.type = 1;
	snprintf(temp_adv.url, sizeof(temp_adv.url), "http://%s/portal/test.html", gateway.lan_ip);

	int tp_size = tempid%5, i = 0;
	tp_size+=1;
	advertising_cfg_t *temp_adv2 = malloc(sizeof(advertising_cfg_t) * tp_size);
	for (i = 0;i < tp_size; i++) {
		memcpy(&temp_adv2[i], &temp_adv, sizeof(temp_adv));
	}
	
	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_DELETE, temp_adv2, sizeof(advertising_cfg_t) * tp_size, NULL, NULL) != 0) {
			printf("MSG_CMD_AS_ADVERTISING_DELETE err\n ");
		}else {
			printf("adv delete success\n");
			}
	free(temp_adv2);
}

/*
void query_advertise()
{
	temp_adv.id = 1;
	temp_adv.type = 1;
	snprintf(temp_adv.url, sizeof(temp_adv.url), "http://ss0.bdstatic.com/jquery-1.10.2_d88366fd.js")
	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_QUERY, temp_adv, sizeof(temp_adv), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_ADVERTISING_DELETE err\n ");
		}else {
			printf("adv delete success");
			}
}
*/

advertising_policy_t temp_policy;
int temp_ssss = 0;

void set_adv_policy()
{
	char **array = NULL;
	char *res;
	int num = 0;
	if (!uuci_get("acct_config.adv_config.adv_policy", &array, &num)) {
		temp_policy.policy = atoi(array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("acct_config.adv_config.adv_option", &array, &num)) {
		temp_policy.option = atoi(array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("acct_config.adv_config.adv_type", &array, &num)) {
		temp_policy.type = atoi(array[0]);
		uuci_get_free(array, num);
	}
	if (!uuci_get("acct_config.adv_config.time_interval", &array, &num)) {
		temp_policy.time_interval= simple_strtoull(array[0], &res, 10);
		uuci_get_free(array, num);
	}
	if (!uuci_get("acct_config.adv_config.flow_interval", &array, &num)) {
		temp_policy.flow_interval= simple_strtoull(array[0], &res, 10);
		uuci_get_free(array, num);
	}

	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_POLICY_SET, &temp_policy, sizeof(temp_policy), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_ADVERTISING_POLICY_SET err\n ");
		}else {
			printf("adv_policy set success\n");
		}
}

void query_adv_policy()
{
	int policy_size = 0;
	advertising_policy_t *res_policy = NULL;
	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_POLICY_QUERY, NULL, 0, &res_policy, &policy_size) != 0) {
			printf("MSG_CMD_AS_ADVERTISING_POLICY_QUERY err\n ");
	}else {
			printf("policy query success policy_oprion = %d\n", res_policy->option);
			free_rcv_buf(res_policy);
			
	}
} 

int portal_url_set()
{
	portal_cfg_t portal;
	portal.apply = 1;
	portal.vlan_id = 3;
	snprintf(portal.url, sizeof(portal.url) - 1, "http://%s/cgi-bin/portal_cgi?opt=query", gateway.lan_ip);
	
	if (msg_send_syn( MSG_CMD_AS_PORTAL_ADD, &portal, sizeof(portal), NULL, 0) != 0) {
		printf("MSG_CMD_AS_PORTAL_URL_SET err\n ");
	}else {
		printf("MSG_CMD_AS_PORTAL_URL_SET success \n");
	}
	portal.apply = 1;
	portal.vlan_id = 1;
	snprintf(portal.url, sizeof(portal.url) - 1, "http://%s/cgi-bin/portal_cgi?opt=query", gateway.lan_ip);
	
	if (msg_send_syn( MSG_CMD_AS_PORTAL_ADD, &portal, sizeof(portal), NULL, 0) != 0) {
		printf("MSG_CMD_AS_PORTAL_URL_SET err\n ");
	}else {
		printf("MSG_CMD_AS_PORTAL_URL_SET success \n");
	}

}

int main (int argc, char **argv)
{
	
	int ret = 0, i = 0;
	gateway_info_init();
	pthread_mutex_init(&query_mutex, NULL);
	pthread_mutex_init(&text_mutex, NULL);
	pthread_mutex_init(&authing_mutex, NULL);
	ret = socketpair(PF_UNIX, SOCK_STREAM, 0, pipefd);
	if (ret == -1)
		return -1;
	
	msg_init(MODULE_MANAGE);
	msg_cmd_register(MSG_CMD_MANAGE_USER_QUERY, user_query_handler);
	msg_cmd_register(MSG_CMD_MANAGE_USER_REGISTER, user_register_handler);
	msg_cmd_register(MSG_CMD_MANAGE_TEXT_SEND, send_tel_code_handler);
	msg_dst_module_register_netlink(MODULE_AS);
	msg_dst_module_register_unix(MODULE_RADIUS);
	
	signal(SIGINT, sig_hander);
	signal(SIGTERM, sig_hander);
	timer_list_init(1, sig_hander);
	
	struct timeval tv;
	fd_set fds;
	int max_fd = 0;
	add_timer(send_heart_beat, 2, 1, 60);
	portal_url_set();
	black_white_list_add_send();
	add_advertise();
//	add_timer(gateway_info_update, 1, 1, 5);
	while (1) {
//		gateway_info_update();
//		if (send_heart_beat())
//			printf("heart_beat error\n");
//		else 
//			printf("heart_beat success\n");
//		sleep(20);

//		sleep(20);
//		black_list_add_send();
//		sleep(20);
//		black_list_del_send();
//		add_timer(add_advertise, 60, 1, 120);
//		add_timer(delete_advertise, 120, 1, 120);
//		add_timer(set_adv_policy, 30, 1, 60);
//		add_timer(query_adv_policy, 60, 1, 60);

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
			ret = recv(pipefd[0], signals, sizelen(signals), 0);
			if (ret > 0) {
				for(i = 0; i < ret; i++) {
					switch(signals[i]) {
					case SIGTERM:
					case SIGINT:
						msg_final(); 
						exit(0);
						break;
					case SIGALRM:
						timer_handler();
						break;
					}
				}
			}
		}

	}

	return 0;

}
