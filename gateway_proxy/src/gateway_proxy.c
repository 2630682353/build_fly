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

#define MAX_JSON_LEN 2048
#define GMC_URL "http://192.168.20.1:81/cgi-bin/temp_cgi?opt=check_login"

static int pipefd[2];

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

typedef struct user_query_info
{
	int auth_type;
	union {
		struct {
			char tel[20];		//字符串
			char pwd[20];		//字符串
		} tel_user;
		struct {
			char username[20];
			char pwd[20];
		} name_user;
		struct {
			char account[20];
			char pwd[20];
		} wechat_user;
	} user;
	unsigned char mac[6];
}user_query_info_t;

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

int32 gateway_query_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	printf("%s\n", ibuf);
	char *test_mac = "FF:FF:FF:FF:FF:FE";

	char report_data[MAX_JSON_LEN] = "report_data=";
	char encode_report[MAX_JSON_LEN] = {0};
	int ret = -1;
	cJSON *root = NULL, *obj = NULL;
	char *jstr = NULL;
	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "stage", "userQuery");
	char *devmac = mac2str(gateway.mac);
	cJSON_AddStringToObject(root, "devMac", devmac);
	free(devmac);
	obj = cJSON_CreateObject();
	cJSON_AddStringToObject(obj, "userMac", ibuf);
	cJSON_AddItemToObject(root, "data", obj);
	obj = NULL;
	jstr = cJSON_PrintUnformatted(root);
	
	urlencode(jstr, encode_report);
	strncat(report_data, encode_report, MAX_JSON_LEN);	
	free(jstr);
	jstr = NULL;
	cJSON_Delete(root);
	jstr = http_post(GMC_URL, report_data); 
	if (!jstr) {
		GATEWAY_LOG("http request return null\n");
		goto out;
	}
//	printf("%s\n", out);
	obj = cJSON_Parse(jstr);
	if (obj)
		printf("%s		   %s\n", obj->child->string, obj->child->valuestring);
	else 
		goto out;
	cJSON *stage = cJSON_GetObjectItem(obj, "stage");
	if (!stage || strcmp(stage->valuestring, "userQuery"))
		goto out;
	cJSON *result = cJSON_GetObjectItem(obj, "result");
	if (!result || strcmp(stage->valuestring, "OK"))
		goto out;	
	cJSON *data = cJSON_GetObjectItem(obj, "data");
	if (!data)
		goto out;
	cJSON *usermac = cJSON_GetObjectItem(data, "userMac");
	if (!usermac || strcmp(usermac->valuestring, ibuf))
		goto out;
	cJSON *auth_type = cJSON_GetObjectItem(data, "authType");
	if (!auth_type)
		goto out;
	user_query_info_t qu;
	memset(&qu, 0, sizeof(user_query_info_t));
	qu.auth_type = 0;
	str2mac(usermac->valuestring, qu.mac);
	switch(auth_type->valueint) {
		cJSON *phone_num = NULL, *wechat = NULL,
			*username = NULL, *password = NULL;
	case 0:
			
		break;
	case 1:
		phone_num = cJSON_GetObjectItem(data, "phoneNumber");
		if (phone_num)
			strncpy(qu.user.tel_user.tel, phone_num->valuestring, sizeof(qu.user.tel_user.tel) - 1);
		break;
	case 2:
		wechat = cJSON_GetObjectItem(data, "wechatAccount");
		if (wechat)
			strncpy(qu.user.wechat_user.account, wechat->valuestring, sizeof(qu.user.wechat_user.account) - 1);
		break;
	case 3:
		username = cJSON_GetObjectItem(data, "username");
		if (username)
			strncpy(qu.user.name_user.username, username->valuestring, sizeof(qu.user.name_user.username) - 1);
		password = cJSON_GetObjectItem(data, "password");
		if (password)
			strncpy(qu.user.name_user.pwd, password->valuestring, sizeof(qu.user.name_user.pwd) - 1);
		break;	
	}
	
	memcpy(obuf, &qu, sizeof(user_query_info_t));
	*olen = sizeof(user_query_info_t);
	
	ret = 0;
out:
	if (jstr)
		free(jstr);
	if (obj)
		cJSON_Delete(obj);
	return ret;
			
}

void sig_hander( int sig )  
{  
	int save_errno = errno;
	int msg = sig;
	send(pipefd[1], (char *)&msg, 1, 0);
	errno = save_errno;
} 

int do_task(cJSON *task_list)
{
	cJSON *child_item = task_list->child;
	while (child_item) {
		cJSON *task_id = cJSON_GetObjectItem(child_item, "id");
		if (task_id) {
			switch(task_id->valueint) {
			case TASK_UPDATE_POTAL_HTML:
				printf("update portal\n");
				break;
			case TASK_UPDATE_AAA_ADDRESS:
				printf("update address\n");
				break;
			}

		}
			
	}

}

int send_heart_beat()
{
	//char report_data[MAX_JSON_LEN] = "report_data=";
	//char encode_report[MAX_JSON_LEN] = {0};
	int ret = -1;
	cJSON *root = NULL, *obj = NULL;
	char *jstr = NULL, *back_str = NULL;
	root = cJSON_CreateObject();
	cJSON_AddStringToObject(root, "stage", "heartbeat");

	cJSON_AddStringToObject(root, "devMac", gateway.mac);
	
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
	
	jstr = cJSON_PrintUnformatted(root);
	
	cJSON_Delete(root);
	printf("gateway:%s\n", jstr);
	
/*
	back_str = http_post(GMC_URL, jstr); 

	if (!back_str) {
		GATEWAY_LOG("http request return null\n");
		goto out;
	}

//	printf("%s\n", out);
	obj = cJSON_Parse(back_str);
	if (obj)
		printf("%s         %s\n", obj->child->string, obj->child->valuestring);
	else 
		goto out;

*/
/*
	cJSON *stage = cJSON_GetObjectItem(obj, "stage");
	if (!stage || strcmp(stage->valuestring, "heartbeat"))
		goto out;
*/


/*
	cJSON *result = cJSON_GetObjectItem(obj, "result");
	if (!result || strcmp(result->valuestring, "OK"))
		goto out;	
	cJSON *data = cJSON_GetObjectItem(obj, "data");
	if (data && data->child && !strcmp(data->child->string, "taskList"))
		do_task(data->child);
	ret = 0;
out:
	if (jstr)
		free(jstr);
	if (back_str)
		free(back_str);
	if (obj)
		cJSON_Delete(obj);
*/
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
	if ((rlen = shell_printf("ifstatus wan | grep \"address\" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'",
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
	if ((rlen = shell_printf("ifstatus wan | grep \"address\" | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'",
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
}

unsigned int black_mac[6] = {0};

void black_list_add_send()
{
	str2mac("02:81:76:f8:69:c2", black_mac);
	if (msg_send_syn( MSG_CMD_AS_BLACKLIST_ADD, black_mac, sizeof(black_mac), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_BLACKLIST_ADD err\n ");
		}else {
			printf("black add success\n");
			}
}

void black_list_del_send()
{
	if (msg_send_syn( MSG_CMD_AS_BLACKLIST_DELETE, black_mac, sizeof(black_mac), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_BLACKLIST_DELETE err\n ");
		}else {
			printf("black delete success\n");
			}
}

advertising_cfg_t temp_adv;
int tempid = 1;
void add_advertise()
{
	temp_adv.id = ++tempid;
	temp_adv.type = 1;
	snprintf(temp_adv.url, sizeof(temp_adv.url), "http://%s/portal/test.html", gateway.lan_ip);
	int tp_size = tempid%5, i = 0;
	tp_size+=3;
	advertising_cfg_t *temp_adv2 = malloc(sizeof(advertising_cfg_t) * tp_size);
	for (i = 0;i < tp_size; i++) {
		memcpy(&temp_adv2[i], &temp_adv, sizeof(temp_adv));
	}
		
	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_ADD, temp_adv2, sizeof(advertising_cfg_t) * tp_size, NULL, NULL) != 0) {
			printf("MSG_CMD_AS_ADVERTISING_ADD err\n ");
		}else {
			printf("adv add success\n");
			}
	free(temp_adv2);
}

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
	temp_ssss++;
	temp_policy.flow_interval = 1024*1024*30;
	if (temp_ssss%2 == 0)
		temp_policy.option = ADS_OPTION_RANDOM;
	else
		temp_policy.option = ADS_OPTION_LOOPING;
	temp_policy.policy = ADS_POLICY_TIME_INTERVAL;
	temp_policy.type = 1;
	temp_policy.time_interval = 10;
	if (msg_send_syn( MSG_CMD_AS_ADVERTISING_POLICY_SET, &temp_policy, sizeof(temp_policy), NULL, NULL) != 0) {
			printf("MSG_CMD_AS_ADVERTISING_POLICY_SET err\n ");
		}else {
			printf("policy set success\n");
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

main (int argc, char **argv)
{
	
	int ret = 0, i = 0;
	gateway_info_init();
	
	ret = socketpair(PF_UNIX, SOCK_STREAM, 0, pipefd);
	if (ret == -1)
		return -1;
	
	msg_init(MODULE_MANAGE);
	msg_cmd_register(MSG_CMD_MANAGE_USER_QUERY, gateway_query_handler);
	msg_dst_module_register_netlink(MODULE_AS);
	
	signal(SIGINT, sig_hander);
	signal(SIGTERM, sig_hander);
	timer_list_init(1, sig_hander);
	
	struct timeval tv;
	fd_set fds;
	int max_fd = 0;
	while (1) {
//		gateway_info_update();
//		if (send_heart_beat())
//			printf("heart_beat error\n");
//		else 
//			printf("heart_beat success\n");
//		sleep(20);

		sleep(20);
		black_list_add_send();
		sleep(20);
		black_list_del_send();
		add_timer(add_advertise, 60, 1, 120);
		add_timer(delete_advertise, 120, 1, 120);
		add_timer(set_adv_policy, 30, 1, 60);
		add_timer(query_adv_policy, 60, 1, 60);
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
