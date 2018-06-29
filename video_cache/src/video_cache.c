#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include	"message.h"
#include    "queue.h"
#include    "list.h"
#include    "libcom.h"
#include     "log.h"
#include     "nlk_ipc.h"
#include     "hash_table.h"
#include <sys/wait.h>
#include <unistd.h>
#include  "igd_md5.h"



static int pipefd[2];
static HashTable *url_video_hash = NULL;
static pthread_mutex_t ht_mutex;

void sig_hander( int sig )  
{  
	int save_errno = errno;
	int msg = sig;
	send(pipefd[1], (char *)&msg, 1, 0);
	errno = save_errno;
} 

int is_youku(char *url)
{
	char *arg1;
	char *arg2;
	char *arg3;
	if (url == NULL)
		return 0;
	arg1 = strchr(url, '?');
	if(arg1 == NULL)
		return 0;
	if (memcmp(arg1 + 1, "ccode", 5))
		return 0;
	arg2 = strchr(arg1, '&');
	if(arg2 == NULL)
		return 0;
	if (memcmp(arg2 + 1, "duration", 8))
		return 0;
	arg3 = strchr(arg2 + 1, '&');
	if(arg3 == NULL)
		return 0;
	if (memcmp(arg3 + 1, "expire", 6))
		return 0;
	return 1;
}

int32 url_handler(const int32 cmd, void *ibuf, int32 ilen, void *obuf, int32 *olen)
{
	
	int ret = -1;
	char url[1500] = "http://";
	char *host = strstr(ibuf, "Host: ");
	char *host_end = strstr(host, "\r\n");
	memcpy(&url[7], host + 6, host_end - host - 6);
	char *first_blank = strchr(ibuf, ' ');
	char *second_blank = strchr(first_blank + 1, ' ');
	memcpy(&url[strlen(url)], first_blank + 1, second_blank - first_blank - 1);	
	printf("url = %s\n", url);
	char url_download[1500] = {0};
	char redirect_url[1500] = "http://";
	strcpy(url_download, url);
	if (is_youku(url)) {
		char cmd[2048] = {0};
		char *end = strstr(url, "&psid");
		*end = '\0';
		char *key = strrchr(url, '/');
		printf("key = %s\n", key + 1);
		int val;
		pthread_mutex_lock(&ht_mutex);
		if ((val = hash_table_get(url_video_hash, key + 1)) == 1) {
			pthread_mutex_unlock(&ht_mutex);
			printf("ssssssssssss, have this key\n");
			char **array = NULL;
			int num = 0;
			if (!uuci_get("network.lan.ipaddr", &array, &num)) {
				strcat(redirect_url, array[0]);
				uuci_get_free(array, num);
			}
			memcpy(&redirect_url[strlen(redirect_url)], first_blank + 1, second_blank - first_blank - 1);	
			memcpy(obuf, redirect_url, strlen(redirect_url) + 1);
			*olen = strlen(redirect_url) + 1;
			ret = 0;
		}
		else if (val == 2) {
			pthread_mutex_unlock(&ht_mutex);
			printf("url is handling\n");
			*olen = 0;
			ret = 0;
		}
		else{
			hash_table_put(url_video_hash, key + 1, 2);
			pthread_mutex_unlock(&ht_mutex);
			unsigned char md5_hash[MD5_HASH_SIZE] = {0};
			oemMD5_CTX file_md5;
			oemMD5Init(&file_md5);
			oemMD5Update(&file_md5, key + 1, strlen(key + 1));
			oemMD5Final(md5_hash, &file_md5);
			char file_name[33] = {0};
			int i = 0;
			for (i = 0; i < 16; i++) {
				snprintf(&file_name[i * 2], 3, "%02x", md5_hash[i]);
			}
			snprintf(cmd, sizeof(cmd) - 1, "wget \"%s\" -T 60 -c -O \"/mnt/mmcblk0p1/video/%s\" --limit-rate=500K", 
			url_download, file_name);
			printf("cmd is %s\n", cmd);
			FILE *fp = NULL;
    		fp = fopen("/tmp/video_wget.sh", "w+");
		    if (fp == NULL)
		        return -1;
    		fprintf(fp, "#!/bin/sh\n%s", cmd);
    		fclose(fp);
			system("/tmp/video_wget.sh ");
			pthread_mutex_lock(&ht_mutex);
			hash_table_put(url_video_hash, key + 1, 1);
			pthread_mutex_unlock(&ht_mutex);
			*olen = 0;
			ret = 0;
		}
	}
	
	return ret;
}

int sig_init()
{
	sigset_t sig;

	sigemptyset(&sig);
	sigaddset(&sig, SIGABRT);
	sigaddset(&sig, SIGPIPE);
	sigaddset(&sig, SIGQUIT);
	sigaddset(&sig, SIGUSR1);
	sigaddset(&sig, SIGUSR2);
	sigaddset(&sig, SIGHUP);
	sigaddset(&sig, SIGALRM);
	pthread_sigmask(SIG_BLOCK, &sig, NULL);
	
	signal(SIGINT, sig_hander);
	signal(SIGTERM, sig_hander);
	return 0;

}


int main(int argc, char **argv)
{
	int i = 0, ret = -1;
	sig_init();
	ret = socketpair(PF_UNIX, SOCK_STREAM, 0, pipefd);
	if (ret == -1)
		return -1;
	msg_init(MODULE_VIDEO_CACHE);
	msg_cmd_register(MSG_CMD_VIDEO_CACHE_URL, url_handler);
	msg_dst_module_register_netlink(MODULE_AS);
	url_video_hash = hash_table_new();
	pthread_mutex_init(&ht_mutex, NULL);
	int fd;
	fd = open("/tmp/video_wget.sh", O_RDWR | O_CREAT | O_TRUNC, 0777);
	close(fd);
	struct timeval tv;
	fd_set fds;
	int max_fd = 0;
	while (1) {

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

