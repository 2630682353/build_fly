#ifndef __CWMP_VERSION_H__
#define __CWMP_VERSION_H__

#include <stdio.h>
#include <time.h>
#include "type.h"
#include "debug.h"

#ifdef  __cplusplus
extern "C" {
#endif
#define MAIN_VERSION    ((int32)1)
#define SUB_VERSION     ((int32)0)
static inline void version_get(int8 *ver)
{
    int8 date[64] = {0};
    time_t now;
    struct tm *tm_now;
    ASSERT(NULL != ver);
    now = time(NULL);
    tm_now = localtime(&now);
    sprintf(date, "%04d%02d%02d", tm_now->tm_year+1900, tm_now->tm_mon+1, tm_now->tm_mday);
    sprintf(ver, "cwmp-%d.%02d-%s", MAIN_VERSION, SUB_VERSION, date);
}

#ifdef  __cplusplus
}
#endif

#endif /*__CWMP_VERSION_H__*/
