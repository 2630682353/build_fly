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


typedef struct user_info
{
	char name[20];		//字符串
	char pwd[20];		//字符串
	unsigned char mac[6];
}user_info_t;

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
	VALUE_PAIR 	*send = NULL, *received = NULL;
	uint32_t		service;
	int result, ret = -1;
	
	if (ilen != sizeof(user_info_t))
		goto error;
	
	user_info_t *u = (user_info_t *)ibuf;

	/*
	  * Fill in User-Name
		 */
	strncpy(username_realm, u->name, sizeof(username_realm));
	/* Append default realm */
	if ((strchr(username_realm, '@') == NULL) && default_realm &&
	    (*default_realm != '\0'))
	{
		strncat(username_realm, "@", sizeof(username_realm)-strlen(username_realm)-1);
		strncat(username_realm, default_realm, sizeof(username_realm)-strlen(username_realm)-1);
	}

	if (rc_avpair_add(rh, &send, PW_USER_NAME, username_realm, -1, 0) == NULL)
		goto error;

	/*
	 * Fill in User-Password
	 */

	if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, u->pwd, -1, 0) == NULL)
		goto error;

	/*
	 * Fill in Service-Type
	 */

	service = PW_AUTHENTICATE_ONLY;
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
}

void sig_hander( int a )  
{  
	
	msg_final(); 
	rc_dict_free(rh);
	rc_config_free(rh);
	exit(0);
} 


main (int argc, char **argv)
{

	
	pname = (pname = strrchr(argv[0],'/'))?pname+1:argv[0];

	rc_openlog(pname);
	if ((rh = rc_read_config(RC_CONFIG_FILE)) == NULL)
		return ERROR_RC;

	if (rc_read_dictionary(rh, rc_conf_str(rh, "dictionary")) != 0)
		return ERROR_RC;
	default_realm = rc_conf_str(rh, "default_realm");
	pthread_mutex_init(&auth_mutex, NULL);

	msg_init(MODULE_RADIUS, 3, "/tmp/radius_rcv", "/tmp/radius_snd");
	msg_cmd_register(RADIUS_AUTH, auth_handler);
	signal(SIGINT, sig_hander);
	
	while (1) {
		sleep(60);
	}

	return 0;

}
