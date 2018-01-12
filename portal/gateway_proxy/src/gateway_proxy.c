#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include    "cJSON.h"
#include	"message.h"
#include    "http_call.h"
#include    "nlk_ipc.h"
#include    "log.h"

#define MAX_JSON_LEN 2048
#define GMC_URL "http://192.168.20.1:81/cgi-bin/temp_cgi?opt=check_login"

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
	int cpu_load;
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

void sig_hander( int a )  
{  
	msg_final(); 
	exit(0);
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
	cJSON_AddNumberToObject(root, "cpu", gateway.cpu_load);
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
	
	if (!sysinfo(&info)) {
		gateway.uptime = info.uptime;
		gateway.cpu_load = info.loads[1];
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
	
	if (!sysinfo(&info)) {
		gateway.uptime = info.uptime;
		gateway.cpu_load = info.loads[1];
		gateway.memory_free = info.freeram;
	}
}

main (int argc, char **argv)
{

	//read_mac(gateway.mac);
	gateway_info_init();
	
	
	msg_init(MODULE_MANAGE);
	msg_cmd_register(MSG_CMD_MANAGE_USER_QUERY, gateway_query_handler);
	signal(SIGINT, sig_hander);
	
	while (1) {
		gateway_info_update();
		if (send_heart_beat())
			printf("heart_beat error\n");
		else 
			printf("heart_beat success\n");
		sleep(20);
	}

	return 0;

}
