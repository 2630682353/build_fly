#ifndef __CWMP_LOG_H__
#define __CWMP_LOG_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"
#include <stdarg.h>
#include <stdlib.h>

#define CGI_LOG_PATH  "/tmp/cgi_log"
#define IPC_LOG_PATH  "/tmp/ipc_log"
#define AAA_LOG_PATH  "/tmp/aaa_log"
#define GATEWAY_LOG_PATH "/tmp/gateway_log"


#define IPC_LOG(fmt,args...) do{ \
    my_log(IPC_LOG_PATH, "[IPC:%05d,%d]:"fmt, __LINE__, getpid(), ##args); \
}while(0)

#define CGI_LOG(fmt,args...) do{ \
    my_log(CGI_LOG_PATH, "[CGI:%05d,%d]:"fmt, __LINE__, getpid(), ##args); \
}while(0)

#define AAA_LOG(fmt,args...) do{ \
    my_log(AAA_LOG_PATH, "[AAA:%05d,%d]:"fmt, __LINE__, getpid(), ##args); \
}while(0)

#define GATEWAY_LOG(fmt,args...) do{ \
    my_log(GATEWAY_LOG_PATH, "[AAA:%05d,%d]:"fmt, __LINE__, getpid(), ##args); \
}while(0)

extern void my_log(char *file, const char *fmt, ...);

#ifdef  __cplusplus
}
#endif

#endif /*__CWMP_LOG_H__*/
