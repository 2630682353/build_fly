#ifndef __CWMP_TIMER_H__
#define __CWMP_TIMER_H__

#include "list.h"
#include "type.h"
#include "error.h"
#include <sys/time.h>

#ifdef  __cplusplus
extern "C" {
#endif

struct cwmp_timer_st;
typedef struct cwmp_timer_st cwmp_timer_t;
typedef void (*timer_func)(cwmp_timer_t *timer);
struct cwmp_timer_st{
    struct list_head list;
    struct timeval time;
    BOOL pending;
    timer_func func;
    void *args;
};

int32 timer_add(cwmp_timer_t *timer);
void timer_cancel(cwmp_timer_t *timer);
int32 timer_set(cwmp_timer_t *timer,
                int32 msecs);
RESULT timer_init(void);
void timer_final(void);

#ifdef  __cplusplus
}
#endif

#endif /*__CWMP_TIMER_H__*/
