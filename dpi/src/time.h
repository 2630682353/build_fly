#ifndef __TIME_H__
#define __TIME_H__

#ifdef  __cplusplus
extern "C" {
#endif


#include <linux/time.h>
#include <linux/rtc.h>
#ifndef curtime
#define curtime()       (get_seconds()-sys_tz.tz_minuteswest * 60)
#endif

#define TIME_MAX        (uint64)(-1)

#ifndef gettimeofday
#define gettimeofday(tv) do_gettimeofday(tv)
#endif
#ifndef _TM_T
#define _TM_T
typedef struct rtc_time tm_t;
#endif
static inline void curtime_tm(tm_t *tm)
{
    struct timeval tv;
    gettimeofday(&tv);
    tv.tv_sec -= sys_tz.tz_minuteswest * 60;
    rtc_time_to_tm(tv.tv_sec, tm);
}
/*
#define TIMESTR         "%04d-%02d-%02d %02d:%02d:%02d"
#define TIME2STR(tm)    (tm)->tm_year+1900,(tm)->tm_mon+1,(tm)->tm_mday,(tm)->tm_hour,(tm)->tm_min,(tm)->tm_sec*/
/*
#define TIME2STR(t)    do{\
                            struct rtc_time tm = rtc_ktime_to_tm(t-(sys_tz.tz_minuteswest*60));\
                            tm.tm_year+1900,tm.tm_mon+1,tm.tm_mday,tm.tm_hour,tm.tm_min,tm.tm_sec\
                        }while(0)
*/
#ifdef  __cplusplus
}
#endif

#endif /*__TIME_H__*/
