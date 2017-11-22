#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include "error.h"
#include "list.h"
#include "def.h"
#include "timer.h"
#include "debug.h"
#include "thread_pool.h"

typedef struct timers_config_st{
    struct list_head timers;
    pthread_mutex_t mutex;
    BOOL inited;
    BOOL cancelled;
    pthread_t thdid;
    thread_pool_t *tpool;
}timers_config_t;

#define TIMERS_THREAD_POOLS_MAXNUM  (1)
static timers_config_t timers_cfg = {LIST_HEAD_INIT(timers_cfg.timers), PTHREAD_MUTEX_INITIALIZER, FALSE, TRUE, -1, NULL};
#define timer_lock()    pthread_mutex_lock(&(timers_cfg.mutex))
#define timer_unlock()  pthread_mutex_unlock(&(timers_cfg.mutex))

static int32 tv_diff(struct timeval *t1, struct timeval *t2)
{
	return  (t1->tv_sec - t2->tv_sec) * 1000 + (t1->tv_usec - t2->tv_usec) / 1000;
}

static void gettime(struct timeval *tv)
{
    gettimeofday(tv, NULL);
}

static void tpool_timer_cb(void *arg)
{
    cwmp_timer_t *timer = (cwmp_timer_t *)arg;
    ASSERT(NULL != timer);
    timer->func(timer);
}

int32 timer_add(cwmp_timer_t *timer)
{
    cwmp_timer_t *tmp = NULL;
    struct list_head *h = &(timers_cfg.timers);
    ASSERT(NULL != timer);

    timer_lock();
    if (TRUE == timers_cfg.cancelled)
    {
        timer_unlock();
        return -1;
    }
    list_for_each_entry(tmp, &(timers_cfg.timers), list)
    {
        if (tv_diff(&tmp->time, &timer->time) > 0)
        {
            h = &tmp->list;
            break;
        }
    }
    timer->pending = TRUE;
    list_add_tail(&timer->list, h);
    timer_unlock();
    return 0;
}

void timer_cancel(cwmp_timer_t *timer)
{
    ASSERT(NULL != timer);
	if (FALSE == timer->pending)
		return;
    timer_lock();
	list_del(&timer->list);
    timer_unlock();
	timer->pending = FALSE;
}


int32 timer_set(cwmp_timer_t *timer,
                int32 msecs)
{
    if (FALSE != timer->pending)
        timer_cancel(timer);
    gettime(&timer->time);
    timer->time.tv_sec += msecs / SEC2MSEC;
    timer->time.tv_usec += (msecs % MSEC2USEC) * MSEC2USEC;
    if (timer->time.tv_usec >= SEC2USEC)
    {
        ++(timer->time.tv_sec);
        timer->time.tv_usec = timer->time.tv_usec - SEC2USEC;
    }
    return timer_add(timer);
}

static int32 timer_run(void)
{
    cwmp_timer_t *t = NULL;
    struct timeval tv;
    int32 num = 0;
    
    gettime(&tv);
    timer_lock();
    while (!list_empty(&(timers_cfg.timers)))
    {
        t = list_first_entry(&(timers_cfg.timers), cwmp_timer_t, list);
        if (tv_diff(&t->time, &tv) > 0)
        {
            //timer_unlock();
            break;
        }
        list_del(&t->list);
        t->pending = FALSE;
        thread_pool_worker_add(timers_cfg.tpool, tpool_timer_cb, (void *)t);
        ++num;
    }
    timer_unlock();
    return num;
}

static void *thread_func(void *arg)
{
    int32 num = 0;
    while (1)
    {
        //DB_INF("thread for timer's callback function timer_func called by OS!!");
        num = timer_run();
        if (num > 0)
            continue;
        timer_lock();
        if ((TRUE == timers_cfg.cancelled) && list_empty(&(timers_cfg.timers)))
        {
            timer_unlock();
            break;
        }
        timer_unlock();
        usleep(USLEEP_INTERVAL);
    }
    return arg;
}

RESULT timer_init(void)
{
    RESULT res = RES_OK;
    pthread_attr_t attr;
    int32 ret = -1;
    BOOL attr_inited = FALSE;

    timer_lock();
    if (TRUE == timers_cfg.inited)
    {
        DB_WAR("timer already inited!!");
        goto out;
    }
    timers_cfg.tpool = thread_pool_create(TIMERS_THREAD_POOLS_MAXNUM);
    if (NULL == timers_cfg.tpool)
    {
        DB_ERR("thread_pool_create() call failed!!");
        res = RES_ERR_THREAD_POOL_CREATE;
        goto out;
    }
    ret = pthread_attr_init(&attr);
    if (0 != ret)
    {
        DB_ERR("pthread_atrr_init() call failed to init thread attr!!");
        res = RES_ERR_THREAD_ATTR_INIT;
        goto out;
    }
    attr_inited = TRUE;
    timers_cfg.cancelled = FALSE;
    ret = pthread_create(&(timers_cfg.thdid), &attr, thread_func, NULL);
    if (0 != ret)
    {
        DB_ERR("pthread_create() call failed to create thread!!");
        res = RES_ERR_THREAD_CREATE;
        goto out;
    }

out:
    if (TRUE == attr_inited)
        pthread_attr_destroy(&attr);
    if (RES_OK != res)
    {
        if (NULL != timers_cfg.tpool)
            thread_pool_destroy(timers_cfg.tpool);
    }
    timer_unlock();
    return res;
}

void timer_final(void)
{
    pthread_t thdid;
    timer_lock();
    if (TRUE == timers_cfg.cancelled)
    {
        timer_unlock();
        return;
    }
    timers_cfg.cancelled = TRUE;
    thdid = timers_cfg.thdid;
    timer_unlock();
    pthread_join(thdid, NULL);
    thread_pool_destroy(timers_cfg.tpool);
}
