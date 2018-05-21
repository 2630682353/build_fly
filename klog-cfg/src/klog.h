#ifndef __KLOG_H__
#define __KLOG_H__

#ifdef  __cplusplus
extern "C" {
#endif

#include "type.h"

typedef enum {
    L_CRIT      = 0,
    L_ERR       = 1,
    L_WARNING   = 2,
    L_NOTICE    = 3,
    L_INFO      = 4,
    L_DEBUG     = 5
}LOG_LEVEL;
#define LOG_LEVEL_VALID(level)  ((level)>=L_CRIT && (level)<=L_DEBUG)

typedef enum logmode_en{
    LOGMODE_SYSLOG  = 0x01,
    LOGMODE_STDOUT  = 0x02,
    LOGMODE_FILE    = 0x04,
    LOGMODE_ALL     = 0x07
}logmode_e;

/* These 16 ioctls are available to devices via the do_ioctl() device
   vector.  Each device should include this file and redefine these
   names as their own. Because these are device dependent it is a good
   idea _NOT_ to issue them to random objects and hope.  */
#ifndef SIOCDEVPRIVATE
#define SIOCDEVPRIVATE  0x89F0  /* to 89FF */
#endif
typedef enum logcmd_en{
    LOGCMD_CHANGE_LEVEL = SIOCDEVPRIVATE + 0x01,
    LOGCMD_GET_LEVEL    = SIOCDEVPRIVATE + 0x02,
    LOGCMD_LOG_ON       = SIOCDEVPRIVATE + 0x03,
    LOGCMD_LOG_OFF      = SIOCDEVPRIVATE + 0x04,
    LOGCMD_LOG_STATUS   = SIOCDEVPRIVATE + 0x05
}logcmd_e;

#ifdef LINUX_APP
void logging(const int32 level,
             int8 *fmt,...);
#define LOGGING_CRIT(fmt,ARGS...)       logging(L_CRIT,fmt,##ARGS)
#define LOGGING_ERR(fmt,ARGS...)        logging(L_ERR,fmt,##ARGS)
#define LOGGING_WARNING(fmt,ARGS...)    logging(L_WARNING,fmt,##ARGS)
#define LOGGING_NOTICE(fmt,ARGS...)     logging(L_NOTICE,fmt,##ARGS)
#define LOGGING_INFO(fmt,ARGS...)       logging(L_INFO,fmt,##ARGS)
#define LOGGING_DEBUG(fmt,ARGS...)      logging(L_DEBUG,fmt,##ARGS)
#elif defined(LINUX_KERNEL)
extern void klog_logging(const int32 level,
                         int8 *fmt,...);
#define LOGGING_CRIT(fmt,ARGS...)       klog_logging(L_CRIT,fmt,##ARGS)
#define LOGGING_ERR(fmt,ARGS...)        klog_logging(L_ERR,fmt,##ARGS)
#define LOGGING_WARNING(fmt,ARGS...)    klog_logging(L_WARNING,fmt,##ARGS)
#define LOGGING_NOTICE(fmt,ARGS...)     klog_logging(L_NOTICE,fmt,##ARGS)
#define LOGGING_INFO(fmt,ARGS...)       klog_logging(L_INFO,fmt,##ARGS)
#define LOGGING_DEBUG(fmt,ARGS...)      klog_logging(L_DEBUG,fmt,##ARGS)
#else
#error "Please define macro 'LINUX_APP' or 'LINUX_KERNEL'."
#endif

#ifdef  __cplusplus
}
#endif

#endif /*__KLOG_H__*/
