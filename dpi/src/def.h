#ifndef __DEF_H__
#define __DEF_H__

#ifdef  __cplusplus
extern "C" {
#endif

#define URL_HTTP_HDR    "http://"
#define URL_HTTPS_HDR   "https://"

#define URL_SIZE                (256)
#define IFNAME_SIZE             (16)
#define HWADDR_SIZE             (6)
#define IPADDR_SIZE             (16)

#define SEC2MSEC                (1000)
#define MSEC2USEC               (1000)
#define SEC2USEC                (1000 * 1000)
#define BYTE_TO_MBYTE           (1024 * 1024)

#define MACSTR          "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(mac)    ((uint8 *)(mac))[0],((uint8 *)(mac))[1],((uint8 *)(mac))[2],((uint8 *)(mac))[3],((uint8 *)(mac))[4],((uint8 *)(mac))[5]

#define IPSTR      "%u.%u.%u.%u"
#define IP2STR(ip) ((uint8 *)(&ip))[0]&0xFF, ((uint8 *)(&ip))[1]&0xFF, ((uint8 *)(&ip))[2]&0xFF, ((uint8 *)(&ip))[3]&0xFF
#ifdef LINUX_APP
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define STR2IP(str) (uint32)inet_addr(str)
#elif defined(LINUX_KERNEL)
#include <linux/inet.h>
#define STR2IP(str) in_aton(str)
#else
#error "Please define macro 'LINUX_APP' or 'LINUX_KERNEL'."
#endif

#ifdef LINUX_APP
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#elif defined(LINUX_KERNEL)
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#ifndef bzero
#define bzero(b,s)  memset(b,0,s)
#endif
#ifndef malloc
#define malloc(s)   kmalloc(s,GFP_KERNEL)
#endif
#ifndef free
#define free(p)     kfree(p)
#endif
#else
#error "Please define macro 'LINUX_APP' or 'LINUX_KERNEL'."
#endif

#ifndef min
#define min(a,b)    ((a)>(b)?(b):(a))
#endif

#ifndef container_of
#define container_of(ptr, type, member)					\
	({								\
		const typeof(((type *) NULL)->member) *__mptr = (ptr);	\
		(type *) ((char *) __mptr - offsetof(type, member));	\
	})
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x)   (sizeof(x) / sizeof((x)[0]))
#endif
/*
#ifndef HTTP_REDIRECT_KTHREAD
#define HTTP_REDIRECT_KTHREAD
#endif*/

#ifdef  __cplusplus
}
#endif

#endif /*__DEF_H__*/
