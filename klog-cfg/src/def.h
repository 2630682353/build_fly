#ifndef __DEF_H__
#define __DEF_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include <linux/string.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/inet.h>

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


#define IPSTR      "%u.%u.%u.%u"
#define IP2STR(ip) ((uint8 *)(&ip))[0]&0xFF, ((uint8 *)(&ip))[1]&0xFF, ((uint8 *)(&ip))[2]&0xFF, ((uint8 *)(&ip))[3]&0xFF
#define STR2IP(str) in_aton(str)
/*
static inline uint32 STR2IP(uint8 *str)
{
    uint32 ip = 0;
    uint32 ip1,ip2,ip3,ip4;
    sscanf(str, "%u.%u.%u.%u", &ip1, &ip2, &ip3, &ip4);
    ((uint8 *)(&ip))[0] = ip1;
    ((uint8 *)(&ip))[1] = ip2;
    ((uint8 *)(&ip))[2] = ip3;
    ((uint8 *)(&ip))[3] = ip4;
    return ip;
}*/

#define MACSTR          "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC2STR(mac)    ((uint8 *)(mac))[0],((uint8 *)(mac))[1],((uint8 *)(mac))[2],((uint8 *)(mac))[3],((uint8 *)(mac))[4],((uint8 *)(mac))[5]

#ifndef container_of
#define container_of(ptr, type, member)					\
	({								\
		const typeof(((type *) NULL)->member) *__mptr = (ptr);	\
		(type *) ((char *) __mptr - offsetof(type, member));	\
	})
#endif

#ifndef bzero
#define bzero(b,s)  memset(b,0,s)
#endif
#ifndef malloc
#define malloc(s)   kmalloc(s,GFP_KERNEL)
#endif
#ifndef free
#define free(p)     kfree(p)
#endif
#ifndef min
#define min(a,b)    ((a)>(b)?(b):(a))
#endif

#ifdef  __cplusplus
}
#endif

#endif /*__DEF_H__*/
