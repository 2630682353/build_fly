#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include	"message.h"

typedef struct user_tel_info
{
	char tel[20];		//字符串
	char pwd[20];		//字符串
	unsigned char mac[6];
}user_tel_info_t;

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



int32 gateway_query_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	printf("%s\n", ibuf);
	char *test_mac = "FF:FF:FF:FF:FF:FE";
	if (strcasecmp(ibuf, test_mac) == 0) {
		user_tel_info_t user;
		strncpy(user.tel, "18202822785", sizeof(user.tel) - 1);
		strncpy(user.pwd, "11111", sizeof(user.pwd) - 1);
		cgi_str2mac(test_mac, user.mac);
		memcpy(obuf, &user, sizeof(user_tel_info_t));
		*olen = sizeof(user_tel_info_t);
		return 0;
	} else {
		*olen = 0;
		return ERR_CODE_QUERYNONE;
	}
			
}

void sig_hander( int a )  
{  
	msg_final(); 
	exit(0);
} 


main (int argc, char **argv)
{

	msg_init(MODULE_RADIUS, 3, "/tmp/gateway_rcv", "/tmp/gateway_snd");
	msg_cmd_register(GATEWAY_QUERY, gateway_query_handler);
	signal(SIGINT, sig_hander);
	
	while (1) {
		sleep(60);
	}

	return 0;

}
